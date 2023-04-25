#
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Copyright (c) 2020 Kyle Evans <kevans@FreeBSD.org>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $FreeBSD$

check_size()
{
	file=$1
	sz=$2

	atf_check -o inline:"$sz\n" stat -f '%z' $file
}

atf_test_case basic
basic_body()
{
	echo "foo" > bar

	atf_check cp bar baz
	check_size baz 4
}

atf_test_case basic_symlink
basic_symlink_body()
{
	echo "foo" > bar
	ln -s bar baz

	atf_check cp baz foo
	atf_check test '!' -L foo

	atf_check -e inline:"cp: baz and baz are identical (not copied).\n" \
	    -s exit:1 cp baz baz
	atf_check -e inline:"cp: bar and baz are identical (not copied).\n" \
	    -s exit:1 cp baz bar
}

atf_test_case chrdev
chrdev_body()
{
	echo "foo" > bar

	check_size bar 4
	atf_check cp /dev/null trunc
	check_size trunc 0
	atf_check cp bar trunc
	check_size trunc 4
	atf_check cp /dev/null trunc
	check_size trunc 0
}

atf_test_case matching_srctgt
matching_srctgt_body()
{

	# PR235438: `cp -R foo foo` would previously infinitely recurse and
	# eventually error out.
	mkdir foo
	echo "qux" > foo/bar
	cp foo/bar foo/zoo

	atf_check cp -R foo foo
	atf_check -o inline:"qux\n" cat foo/foo/bar
	atf_check -o inline:"qux\n" cat foo/foo/zoo
	atf_check -e not-empty -s not-exit:0 stat foo/foo/foo
}

atf_test_case matching_srctgt_contained
matching_srctgt_contained_body()
{

	# Let's do the same thing, except we'll try to recursively copy foo into
	# one of its subdirectories.
	mkdir foo
	ln -s foo coo
	echo "qux" > foo/bar
	mkdir foo/moo
	touch foo/moo/roo
	cp foo/bar foo/zoo

	atf_check cp -R foo foo/moo
	atf_check cp -RH coo foo/moo
	atf_check -o inline:"qux\n" cat foo/moo/foo/bar
	atf_check -o inline:"qux\n" cat foo/moo/coo/bar
	atf_check -o inline:"qux\n" cat foo/moo/foo/zoo
	atf_check -o inline:"qux\n" cat foo/moo/coo/zoo

	# We should have copied the contents of foo/moo before foo, coo started
	# getting copied in.
	atf_check -o not-empty stat foo/moo/foo/moo/roo
	atf_check -o not-empty stat foo/moo/coo/moo/roo
	atf_check -e not-empty -s not-exit:0 stat foo/moo/foo/moo/foo
	atf_check -e not-empty -s not-exit:0 stat foo/moo/coo/moo/coo
}

atf_test_case matching_srctgt_link
matching_srctgt_link_body()
{

	mkdir foo
	echo "qux" > foo/bar
	cp foo/bar foo/zoo

	atf_check ln -s foo roo
	atf_check cp -RH roo foo
	atf_check -o inline:"qux\n" cat foo/roo/bar
	atf_check -o inline:"qux\n" cat foo/roo/zoo
}

atf_test_case matching_srctgt_nonexistent
matching_srctgt_nonexistent_body()
{

	# We'll copy foo to a nonexistent subdirectory; ideally, we would
	# skip just the directory and end up with a layout like;
	#
	# foo/
	#     bar
	#     dne/
	#         bar
	#         zoo
	#     zoo
	#
	mkdir foo
	echo "qux" > foo/bar
	cp foo/bar foo/zoo

	atf_check cp -R foo foo/dne
	atf_check -o inline:"qux\n" cat foo/dne/bar
	atf_check -o inline:"qux\n" cat foo/dne/zoo
	atf_check -e not-empty -s not-exit:0 stat foo/dne/foo
}

recursive_link_setup()
{
	extra_cpflag=$1

	mkdir -p foo/bar
	ln -s bar foo/baz

	mkdir foo-mirror
	eval "cp -R $extra_cpflag foo foo-mirror"
}

atf_test_case recursive_link_dflt
recursive_link_dflt_body()
{
	recursive_link_setup

	# -P is the default, so this should work and preserve the link.
	atf_check cp -R foo foo-mirror
	atf_check test -L foo-mirror/foo/baz
}

atf_test_case recursive_link_Hflag
recursive_link_Hflag_body()
{
	recursive_link_setup

	# -H will not follow either, so this should also work and preserve the
	# link.
	atf_check cp -RH foo foo-mirror
	atf_check test -L foo-mirror/foo/baz
}

atf_test_case recursive_link_Lflag
recursive_link_Lflag_body()
{
	recursive_link_setup -L

	# -L will work, but foo/baz ends up expanded to a directory.
	atf_check test -d foo-mirror/foo/baz -a \
	    '(' ! -L foo-mirror/foo/baz ')'
	atf_check cp -RL foo foo-mirror
	atf_check test -d foo-mirror/foo/baz -a \
	    '(' ! -L foo-mirror/foo/baz ')'
}

file_is_sparse()
{
	atf_check test "$(stat -f "%b" "$1")" != "$(stat -f "%z" "$1")"
}

files_are_equal()
{
	atf_check test "$(stat -f "%d %i" "$1")" != "$(stat -f "%d %i" "$2")"
	atf_check cmp "$1" "$2"
}

atf_test_case sparse_leading_hole
sparse_leading_hole_body()
{
	# A one-megabyte hole followed by one megabyte of data
	truncate -s 1M foo
	seq -f%015g 65536 >>foo
	file_is_sparse foo

	atf_check cp foo bar
	files_are_equal foo bar
	file_is_sparse bar
}

atf_test_case sparse_multiple_holes
sparse_multiple_holes_body()
{
	# Three one-megabyte blocks of data preceded, separated, and
	# followed by one-megabyte holes
	truncate -s 1M foo
	seq -f%015g >>foo
	truncate -s 3M foo
	seq -f%015g >>foo
	truncate -s 5M foo
	seq -f%015g >>foo
	truncate -s 7M foo
	file_is_sparse foo

	atf_check cp foo bar
	files_are_equal foo bar
	file_is_sparse bar
}

atf_test_case sparse_only_hole
sparse_only_hole_body()
{
	# A one-megabyte hole
	truncate -s 1M foo
	file_is_sparse foo

	atf_check cp foo bar
	files_are_equal foo bar
	file_is_sparse bar
}

atf_test_case sparse_to_dev
sparse_to_dev_body()
{
	# Three one-megabyte blocks of data preceded, separated, and
	# followed by one-megabyte holes
	truncate -s 1M foo
	seq -f%015g >>foo
	truncate -s 3M foo
	seq -f%015g >>foo
	truncate -s 5M foo
	seq -f%015g >>foo
	truncate -s 7M foo
	file_is_sparse foo

	atf_check -o file:foo cp foo /dev/stdout
}

atf_test_case sparse_trailing_hole
sparse_trailing_hole_body()
{
	# One megabyte of data followed by a one-megabyte hole
	seq -f%015g 65536 >foo
	truncate -s 2M foo
	file_is_sparse foo

	atf_check cp foo bar
	files_are_equal foo bar
	file_is_sparse bar
}

atf_test_case standalone_Pflag
standalone_Pflag_body()
{
	echo "foo" > bar
	ln -s bar foo

	atf_check cp -P foo baz
	atf_check -o inline:'Symbolic Link\n' stat -f %SHT baz
}

atf_init_test_cases()
{
	atf_add_test_case basic
	atf_add_test_case basic_symlink
	atf_add_test_case chrdev
	atf_add_test_case matching_srctgt
	atf_add_test_case matching_srctgt_contained
	atf_add_test_case matching_srctgt_link
	atf_add_test_case matching_srctgt_nonexistent
	atf_add_test_case recursive_link_dflt
	atf_add_test_case recursive_link_Hflag
	atf_add_test_case recursive_link_Lflag
	atf_add_test_case sparse_leading_hole
	atf_add_test_case sparse_multiple_holes
	atf_add_test_case sparse_only_hole
	atf_add_test_case sparse_to_dev
	atf_add_test_case sparse_trailing_hole
	atf_add_test_case standalone_Pflag
}
