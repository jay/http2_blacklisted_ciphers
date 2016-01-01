#!/usr/bin/env perl

=begin comment
README

This script looks up the ids of cipher suites on the TLS 1.2 cipher suite
blacklist from HTTP/2 RFC 7540 and outputs a list in a C struct format. It also
makes several C methods that can be used to test whether a cipher is banned.

Note that according to HTTP/2 RFC 7540 the blacklist enforcement is described
using the RFC semantic 'MAY' which is the same as 'OPTIONAL'. In this script I
refer to the ciphers as just blacklisted or banned.

./make_c_test_http2_blacklist.pl > runtests.c
gcc -std=c89 -ansi -pedantic -Wall -Wextra -O3 -o runtests runtests.c
./runtests

Copyright (C) 2015 Jay Satiro <raysatiro@yahoo.com>
http://curl.haxx.se/docs/copyright.html

https://github.com/jay/http2_blacklisted_ciphers
https://github.com/bagder/curl/pull/406
=end comment
=cut

use strict;
use warnings;

use Data::Dumper;

sub strlen($) { defined($_[0]) ? length($_[0]) : 0; }

sub make_hexstr($)
{
  my $hexstr = sprintf("%X", $_[0]);
  $hexstr = "0$hexstr" if length($hexstr) & 1;
  $hexstr = "0x$hexstr";
  return $hexstr;
}

# hashes of all and banned ciphers
# key: name
# value: id
my %all;
my %banned;

my $fh;
my $filename;

$filename = "all_cipher_ids.txt";
open($fh, "<:crlf", $filename) || die "Can't open $filename ($!)";

while(<$fh>) {
  next if /^#/ || /^$/;

  if(!/^0?x([a-fA-F0-9]{1,6})[ \t]+(\S+).*$/) {
    warn "Unable to parse $filename line $.:\n$_\n";
    next;
  }

  $all{$2} = hex($1);
}

close($fh);

$filename = "http2_blacklisted_ciphers.txt";
open($fh, "<:crlf", $filename) || die "Can't open $filename ($!)";

while(<$fh>) {
  next if /^#/ || /^$/;

  if(!/^[ \t]*(\S+)[ \t]*$/) {
    warn "Unable to parse $filename line $.:\n$_\n";
    next;
  }

  defined $all{$1} || die "Can't find id for blacklisted cipher $1";

  $banned{$1} = $all{$1};
}

close($fh);


#use Data::Dumper;
#print Dumper(\%banned);

#printf(STDERR "$_ => 0x%02X\n", $all{$_}) for (sort keys %all);
#printf(STDERR "$_ => 0x%02X\n", $banned{$_}) for (sort keys %banned);

#printf(STDERR "0x%02X\n", $_) for (sort values %banned);

#printf(STDERR "$_ => 0x%02X\n", $banned{$_}) for (sort keys %banned);


# append_id_to_logic
#
# This is a helper function that is called as we iterate through a list of
# sorted banned cipher ids. It makes $logic, a C conditional logic string that
# can be used in C to test if a cipher id is banned.
#
# eg "(0xAC <= id && id <= 0xC5) || id == 0xFF || etc || etc"
#
# Pass the current cipher id as a parameter. The id must be >= the previous.
#
# This function saves its state to calculate id ranges. It will typically not
# write the logic for the current id right away. Call with parameter undef to
# signal finished which will reset the state and append any remaining logic.
my $logic;
{
my $bip; # counter for the number of ids on the current line
my $range_start;
my $range_end;
sub append_id_to_logic($)
{
  my $id = $_[0];

  if(defined $id) {
    if(!defined $range_start) {
      $range_start = $id;
      undef $logic;
      return;
    }

    # Ignore duplicate cipher ids
    return if $id == ($range_end || $range_start);

    # Extend the range if possible
    if((!defined $range_end && $range_start + 1 == $id) ||
       (defined $range_end && $range_end + 1 == $id)) {
      $range_end = $id;
      return;
    }
  }
  elsif(!defined $range_start) {
    # The function was called with undef but no ids were supplied beforehand.
    die; # In the current configuration this shouldn't ever happen.
  }

  # The range can't be extended or no id was specified (ie flush and cleanup).
  # Write existing range to $logic.
  # If $id use it to start a new range.
  # For example:
  # range_start: 0xC0A0
  # range_end:   0xC0A1
  # id:          0xC0A4
  # 0xC0A2 != 0xC0A4. Therefore 0xC0A2 and 0xC0A3 aren't banned ids.
  # Range 0xC0A0 - 0xC0A1 will be written and 0xC0A4 will start a new range.

  #print "\$range_start: $range_start\n\$range_end: $range_end\n";

  $range_end = $range_start if !defined $range_end;

  $logic .= (!defined $logic ? "( \\\n " : " ||");

  # Start a new line if there are >= 3 ids on the current line
  if(defined $bip && $bip >= 3) {
    $bip = 0;
    $logic .= " \\\n ";
  }

  $logic .= " ";

  if($range_start == $range_end) {
    $logic .= "id == " . make_hexstr($range_start);
    $bip += 1;
  }
  elsif($range_start + 1 == $range_end) {
    $logic .= "id == " . make_hexstr($range_start) .
              " || id == " . make_hexstr($range_end);
    $bip += 2;
  }
  else {
    $logic .= "(" . make_hexstr($range_start) . " <= id" .
              " && id <= " . make_hexstr($range_end) . ")";
    $bip += 2;
  }

  $range_start = $id;
  undef $range_end;

  if(!defined $id) {
    undef $bip;
    $logic .= " \\\n)";
  }
}
}

# In addition to the regular conditional logic we can use a lookup table for
# alternative conditional logic.
#
# In the case of HTTP/2 banned cipher ids they are always in these ranges:
# 0x0000 - 0x00FF
# 0xC000 - 0xC0FF
#
# Therefore we can have two lookup tables. The key will be the hibyte (00 or
# C0) and the value will be an array of integers that we use to map the lobyte
# by representing each as a bit in an integer.
my %lookup;

# As another alternative make the banned ids into case expressions for switch.
my $cases;
my $cases_bip; # counter for the number of ids on the current line

# Generate a C array string of blacklisted ciphers sorted by id (equal ids
# sorted by name). Also generate the first conditional logic string, generate
# case expressions and create a lookup table for the alternative logic string.
my $ciphers_by_id;
for(sort {$banned{$a} <=> $banned{$b} || ($a cmp $b)} keys %banned) {
  $ciphers_by_id .= (!defined $ciphers_by_id ? "{" : ",") . "\n";
  $ciphers_by_id .= "  { " . make_hexstr($banned{$_}) . ", \"$_\" }";

  append_id_to_logic($banned{$_});

  if(defined $cases_bip && $cases_bip >= 5) {
    $cases .= "\n";
    $cases_bip = 0;
  }
  $cases .= " " if !$cases_bip;
  $cases .= " case " . make_hexstr($banned{$_}) . ":";
  $cases_bip++;

  #
  # Create lookup table
  #
  if($banned{$_} > 0xFFFF) {
    die "Fatal: Cipher ids larger than 0xFFFF aren't supported.\n";
  }
  elsif(!(0x0000 <= $banned{$_} && $banned{$_} <= 0x00FF) &&
        !(0xC000 <= $banned{$_} && $banned{$_} <= 0xC0FF)) {
    die "Fatal: Unrecognized cipher id " . make_hexstr($banned{$_});
  }

  my $lobyte = $banned{$_} & 0xFF;
  my $hibyte = ($banned{$_} >> 8) & 0xFF;

  # pack the id in a lookup table
  $lookup{$hibyte}[$lobyte / 8] |= 1 << ($lobyte % 8);
}
$ciphers_by_id .= "\n};";
append_id_to_logic(undef); # append any remaining logic to $logic

# Generate alternative conditional logic based on lookup table
my $altlogic;
for(sort {$a <=> $b} keys %lookup) {
  $altlogic .= (!defined $altlogic ? "(" : " ||") . " \\\n";

  my $key = make_hexstr($_);
  $altlogic .= "  ($key" . "00 <= id && id <= $key" . "FF && \\\n";

  for my $i (0 .. 31) {
    $altlogic .= "    \"" if $i == 0 || $i == 16;
    $altlogic .= sprintf("\\x%02X", $lookup{$_}[$i] || 0);
    $altlogic .= "\" \\\n" if $i == 15 || $i == 31;
  }

  $altlogic .= "    [(id & 0xFF) / 8] & (1 << (id % 8)))";
}
$altlogic .= " \\\n)";

my $out =
'
/*
Test the performance of methods used to check for cipher suites on the TLS 1.2
cipher suite blacklist from HTTP/2 RFC 7540.

This file was generated by make_c_test_http2_blacklist.pl.

Copyright (C) 2015 Jay Satiro <raysatiro@yahoo.com>
http://curl.haxx.se/docs/copyright.html

https://github.com/jay/http2_blacklisted_ciphers
https://github.com/bagder/curl/pull/406
*/

#include <stdio.h>
#include <stdlib.h>
#include <search.h>
#include <time.h>

#undef FALSE
#define FALSE 0

#undef TRUE
#define TRUE 1

struct cipher {
  int id;
  const char *name;
};

/* HTTP/2 - RFC OPTIONAL banned ciphers sorted by id */
struct cipher banned_ciphers[] = ' . $ciphers_by_id . '

/* Simple loop to check if id is banned */
int IsCipherBannedMethod0(int id)
{
  unsigned i;

  for(i = 0; i < sizeof banned_ciphers / sizeof banned_ciphers[0]; ++i) {
    if(id < banned_ciphers[i].id)
      return FALSE;
    else if(id == banned_ciphers[i].id)
      return TRUE;
  }

  return FALSE;
}

/* Conditional logic to check if id is banned */
#define IS_CIPHER_BANNED_METHOD1(id) ' . $logic . '

/* Conditional logic w/ lookup tables to check if id is banned */
#define IS_CIPHER_BANNED_METHOD2(id) ' . $altlogic . '

int CompareCipherId(const void *id, const void *cipher)
{
  return *(int *)id < ((struct cipher *)cipher)->id ? -1 :
           *(int *)id > ((struct cipher *)cipher)->id ? 1 : 0;
}

/* Binary search to check if id is banned */
int IsCipherBannedMethod3(int id)
{
  return !!bsearch(&id, banned_ciphers,
                   sizeof banned_ciphers / sizeof banned_ciphers[0],
                   sizeof banned_ciphers[0], CompareCipherId);
}

/* Switch statement to check if id is banned */
int IsCipherBannedMethod4(int id)
{
  switch(id) {
' . $cases . '
    return TRUE;
  }
  return FALSE;
}

void *malloc_or_die(size_t bytes)
{
  void *p;

  p = malloc(bytes);
  if(!p) {
    fprintf(stderr, "Fatal: Out of memory.\n");
    exit(EXIT_FAILURE);
  }

  return p;
}

#define ID_COUNT      10000000
#define METHOD_COUNT  5

#if METHOD_COUNT > 9
#error "Fix method name parsing for more than a single digit, see method_num"
#endif

int main(int argc, char *argv[])
{
  int i;
  int *random_ids;
  int **results;

  (void)argc;
  (void)argv;

  random_ids = malloc_or_die(ID_COUNT * sizeof *random_ids);
  results = malloc_or_die(METHOD_COUNT * sizeof *results);
  for(i = 0; i < METHOD_COUNT; ++i) {
    results[i] = malloc_or_die(ID_COUNT * sizeof **results);
  }

  printf("Generating %d random ids.\n", ID_COUNT);

  srand((unsigned)time(NULL));
  for(i = 0; i < ID_COUNT; ++i) {
    random_ids[i] = rand() & 32767;
  }

/* Call with method 0 first since we compare against that result table. */
#define TEST_METHOD(method, description) { \
  int method_num; \
  clock_t start, end; \
  \
  method_num = #method[sizeof #method - 2] - 48; \
  if(method_num < 0 || method_num >= METHOD_COUNT) { \
    fprintf(stderr, "Fatal: Unrecognized method: %s\n", #method); \
    exit(EXIT_FAILURE); \
  } \
  \
  printf("\nTesting method %d: %s: %s.\n", \
         method_num, #method, description); \
  \
  start = clock(); \
  for(i = 0; i < ID_COUNT; ++i) { \
    results[method_num][i] = method(random_ids[i]); \
  } \
  end = clock(); \
  \
  printf("%s took %f seconds.\n", \
         #method, ((double) (end - start)) / CLOCKS_PER_SEC); \
  \
  if(method_num) { \
    for(i = 0; i < ID_COUNT; ++i) { \
      if(results[0][i] != results[method_num][i]) { \
        fprintf(stderr, "Fatal: Test of method %d failed: id 0x%x is %s.\n", \
                method_num, results[method_num][i], \
                results[method_num][i] ? "TRUE" : "FALSE"); \
        exit(EXIT_FAILURE); \
      } \
    } \
  } \
}

  TEST_METHOD(IsCipherBannedMethod0, "simple loop");
  TEST_METHOD(IS_CIPHER_BANNED_METHOD1, "conditional logic");
  TEST_METHOD(IS_CIPHER_BANNED_METHOD2, "conditional logic w/ lookup tables");
  TEST_METHOD(IsCipherBannedMethod3, "binary search");
  TEST_METHOD(IsCipherBannedMethod4, "switch statement");

  return EXIT_SUCCESS;
}
';
$out =~ s/\r//g;
print $out;
