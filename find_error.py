#!/usr/bin/perl

use strict;
use Getopt::Long;
use File::Copy;

# Check usage

my %args = handle_commandline_arguments();

my ($lines_before, $lines_after, $line);
my $base_record_file = "record.dmp";
my $base_tmp_log_file = "partial.log";
my @log_lines;
my ($record_file, $tmp_log_file,$iteration, $pid);
my $karim= "1";
my $karim2;
my $karim3;

$SIG{INT} = $SIG{TERM} = sub {
    if (-f $args{output_file} && $args{zip}) {
        `gzip $args{output_file}`;
    }
    exit;
};

for($iteration = 1; 1 ;$iteration++)
{
        # Get the number of lines before the recording
        $lines_before = &CountLines($args{log_file});

        $record_file = "$base_record_file.$iteration";
        $tmp_log_file = "$base_tmp_log_file.$iteration";

        # Record the network traffic
        my $status;
    $pid = fork();
    if (! defined $pid) {
        die "cannot fork";
        exit 1;
    } elsif ($pid == 0) {
        select(STDERR); $| = 1;     # make unbuffered
        select(STDOUT); $| = 1;     # make unbuffered
        exec "tcpdump -i $args{interface} -c $args{num_packets} -s $args{snap} -w $record_file $args{expression}";
    } else {
        wait();
        $status = $? >> 8;
    }

        print "Recorded traffic, return value of tcpdump was $status\n";

        # Get the number of lines after the execution
        $lines_after =  &CountLines($args{log_file});

        # Fetch all the relevant lines
        my $cmd = "tail -".($lines_after - $lines_before)." $args{log_file} > $tmp_log_file";
        @log_lines = `$cmd`;

        # open the partial log
        open LOG, $tmp_log_file or die "Could not open $tmp_log_file : $!\n";
        my $found_flag = 0;
        my $line_ind = 0;

        # Search for the token on the log file
        foreach $line(<LOG>)
        {
                $line_ind++;
                if(index($line, $args{token}) >= 0)
                {
                        $found_flag = 1;
                        print "Found $args{token} at line $line_ind of the partial log -file name $tmp_log_file (line ".($lines_before + $line_ind)." on the original)\n";
                }
        }

    close LOG;

        # if found - append the files create a tar file at the given location
        if($found_flag)
        {
         $karim3 = "$args{output_file}$karim" ;
        `tar rvf $karim3 $tmp_log_file $record_file`;

        $karim++ ;

        }
        else
        {
                print "The signature $args{token} was not found during the recording\n";
        }

        # Remove the temporary files
        my $file;
        foreach $file ($tmp_log_file, $record_file)
        {
                $status = unlink $file;
                if($status != 1)
                {
                        print "Failed to remove $file: $!. The file should be removed manually\n";
                }
        }
        sleep 1;
}

sub CountLines
{
        my $file = shift;
    open(my $in, $file);
    my $n = 0;
    $n++ while <$in>;
    close($in);
    return $n;
}

sub handle_commandline_arguments {
    my %arguments;
    my $rv = GetOptions (
        "t|token=s"       => \$arguments{token},
        "l|log_file=s"    => \$arguments{log_file},
        "p|num_packets=i" => \$arguments{num_packets},
        "o|output_file=s" => \$arguments{output_file},
        "zip!"            => \$arguments{zip},
        "i|interface=s"   => \$arguments{interface},
        "e|expression=s"  => \$arguments{expression},
        "s|snap=i"        => \$arguments{snap},
        "nnn!"            => \$arguments{nnn},
        "h|help"          => \$arguments{help},
    );

    $arguments{interface} ||= "0.0";
    if (($arguments{nnn}) || (!defined $arguments{nnn})) {
        if ($arguments{interface} =~ /:/) {
            $arguments{interface} .= 'nnn';
        }
        else {
            $arguments{interface} .= ':nnn';
        }
    }

    $arguments{snap} = 0 unless defined $arguments{snap};
    $arguments{expression} = "" if $arguments{expression} eq "''";
    if ($arguments{expression} && $arguments{expression} !~ /^'(.*)'$/) {
        $arguments{expression} = "'$arguments{expression}'";
    }

    if ($arguments{output_file} =~ /(.*)\.gz$/) {
        my $tmp_file = $1;
        $arguments{output_file} = $tmp_file;
    }

    my ($tmp_filename) = $arguments{output_file} =~ /(.*)\.gz$/;

    unlink $arguments{output_file}.".gz" if -f $arguments{output_file}.".gz";
    unlink $arguments{output_file}       if -f $arguments{output_file};
    unlink $tmp_filename                 if -f $tmp_filename;


    unless ($rv) {
        print usage();
        exit 1;
    }

    if ($arguments{help}) {
        print usage();
        exit 0;
    }

    return %arguments;
}

sub usage {
    return qq{
USAGE:
    $0 <mandatory arguments>

Mandatory arguments:

    -t, --token='Token'
        the token you are searching for

    -l, --log_file='Log File'
        fullpath/filename of log file to use for logging

    -p, --packet_num='Packet Number'
        the number of the packets to dump

    -o, --output_file='Output File'
        fullpath/filename of the output file to use


Optional arguments:

    --zip='zip tar file'
        to zip the final tar file

    --nozip='do not zip tar file'
        not to zip the final tar file

    -e, --expression='filter expression'
        filtering expression for tcpdump

    -i, --interface='Interface'
        Default: 0.0

    -s, --snap='Snap length'
        Default: 0

    --nnn='use nnn to increasing amounts of internal debugging information appended to the end of each packet'
        Default: nnn

    -h, --help='help'
        issue this help message.
    \n};
}
