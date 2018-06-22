# $FreeBSD$

atf_test_case simple
atf_test_case unified
atf_test_case header
atf_test_case header_ns
atf_test_case ifdef
atf_test_case group_format
atf_test_case side_by_side
atf_test_case brief_format

simple_body()
{
	atf_check -o file:$(atf_get_srcdir)/simple.out -s eq:1 \
		diff "$(atf_get_srcdir)/input1.in" "$(atf_get_srcdir)/input2.in"

	atf_check -o file:$(atf_get_srcdir)/simple_e.out -s eq:1 \
		diff -e "$(atf_get_srcdir)/input1.in" "$(atf_get_srcdir)/input2.in"

	atf_check -o file:$(atf_get_srcdir)/simple_u.out -s eq:1 \
		diff -u -L input1 -L input2 "$(atf_get_srcdir)/input1.in" "$(atf_get_srcdir)/input2.in"

	atf_check -o file:$(atf_get_srcdir)/simple_n.out -s eq:1 \
		diff -n "$(atf_get_srcdir)/input1.in" "$(atf_get_srcdir)/input2.in"

	atf_check -o inline:"Files $(atf_get_srcdir)/input1.in and $(atf_get_srcdir)/input2.in differ\n" -s eq:1 \
		diff -q "$(atf_get_srcdir)/input1.in" "$(atf_get_srcdir)/input2.in"

	atf_check \
		diff -q "$(atf_get_srcdir)/input1.in" "$(atf_get_srcdir)/input1.in"

	atf_check -o file:$(atf_get_srcdir)/simple_i.out -s eq:1 \
		diff -i "$(atf_get_srcdir)/input_c1.in" "$(atf_get_srcdir)/input_c2.in"

	atf_check -o file:$(atf_get_srcdir)/simple_w.out -s eq:1 \
		diff -w "$(atf_get_srcdir)/input_c1.in" "$(atf_get_srcdir)/input_c2.in"

	atf_check -o file:$(atf_get_srcdir)/simple_b.out -s eq:1 \
		diff -b "$(atf_get_srcdir)/input_c1.in" "$(atf_get_srcdir)/input_c2.in"

	atf_check -o file:$(atf_get_srcdir)/simple_p.out -s eq:1 \
		diff --label input_c1.in --label input_c2.in -p "$(atf_get_srcdir)/input_c1.in" "$(atf_get_srcdir)/input_c2.in"
}

unified_body()
{
	atf_check -o file:$(atf_get_srcdir)/unified_p.out -s eq:1 \
		diff -up -L input_c1.in -L input_c2.in  "$(atf_get_srcdir)/input_c1.in" "$(atf_get_srcdir)/input_c2.in"
	atf_check -o file:$(atf_get_srcdir)/unified_c9999.out -s eq:1 \
		diff -u -c9999 -L input_c1.in -L input_c2.in "$(atf_get_srcdir)/input_c1.in" "$(atf_get_srcdir)/input_c2.in"
	atf_check -o file:$(atf_get_srcdir)/unified_9999.out -s eq:1 \
		diff -u9999 -L input_c1.in -L input_c2.in "$(atf_get_srcdir)/input_c1.in" "$(atf_get_srcdir)/input_c2.in"
}

header_body()
{
	export TZ=UTC
	: > empty
	echo hello > hello
	touch -d 2015-04-03T01:02:03 empty
	touch -d 2016-12-22T11:22:33 hello
	atf_check -o "file:$(atf_get_srcdir)/header.out" -s eq:1 \
		diff -u empty hello
}

header_ns_body()
{
	export TZ=UTC
	: > empty
	echo hello > hello
	touch -d 2015-04-03T01:02:03.123456789 empty
	touch -d 2016-12-22T11:22:33.987654321 hello
	atf_check -o "file:$(atf_get_srcdir)/header_ns.out" -s eq:1 \
		diff -u empty hello
}

ifdef_body()
{
	atf_check -o file:$(atf_get_srcdir)/ifdef.out -s eq:1 \
		diff -D PLOP "$(atf_get_srcdir)/input_c1.in" \
		"$(atf_get_srcdir)/input_c2.in"
}

group_format_body()
{
	atf_check -o file:$(atf_get_srcdir)/group-format.out -s eq:1 \
		diff --changed-group-format='<<<<<<< (local)
%<=======
%>>>>>>>> (stock)
' "$(atf_get_srcdir)/input_c1.in" "$(atf_get_srcdir)/input_c2.in"
}

side_by_side_body()
{
	atf_expect_fail "--side-by-side not currently implemented (bug # 219933)"

	atf_check -o save:A printf "A\nB\nC\n"
	atf_check -o save:B printf "D\nB\nE\n"

	exp_output="A[[:space:]]+|[[:space:]]+D\nB[[:space:]]+B\nC[[:space:]]+|[[:space:]]+E"
	exp_output_suppressed="A[[:space:]]+|[[:space:]]+D\nC[[:space:]]+|[[:space:]]+E"

	atf_check -o match:"$exp_output" -s exit:1 \
	    diff --side-by-side A B
	atf_check -o match:"$exp_output" -s exit:1 \
	    diff -y A B
	atf_check -o match:"$exp_output_suppressed" -s exit:1 \
	    diff -y --suppress-common-lines A B
	atf_check -o match:"$exp_output_suppressed" -s exit:1 \
	    diff -W 65 -y --suppress-common-lines A B
}

brief_format_body()
{
	atf_check mkdir A B

	atf_check -x "echo 1 > A/test-file"
	atf_check -x "echo 2 > B/test-file"

	atf_check cp -Rf A C
	atf_check cp -Rf A D

	atf_check -x "echo 3 > D/another-test-file"

	atf_check \
	    -s exit:1 \
	    -o inline:"Files A/test-file and B/test-file differ\n" \
	    diff -rq A B

	atf_check diff -rq A C

	atf_check \
	    -s exit:1 \
	    -o inline:"Only in D: another-test-file\n" \
	    diff -rq A D

	atf_check \
	    -s exit:1 \
	    -o inline:"Files A/another-test-file and D/another-test-file differ\n" \
	    diff -Nrq A D
}

atf_init_test_cases()
{
	atf_add_test_case simple
	atf_add_test_case unified
	atf_add_test_case header
	atf_add_test_case header_ns
	atf_add_test_case ifdef
	atf_add_test_case group_format
	atf_add_test_case side_by_side
	atf_add_test_case brief_format
}
