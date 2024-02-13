#include <sys/param.h>

#include <map>
#include <string>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <graphviz/cgraph.h>
#include <graphviz/gvc.h>

using namespace std::string_literals;

typedef enum {
	NODE_TYPE_INVALID,
	NODE_TYPE_FUNCTION,
	NODE_TYPE_COMPARTMENT
} node_type_t;

typedef enum {
	FORMAT_TYPE_INVALID,
	FORMAT_TYPE_D2,
	FORMAT_TYPE_D3_ARC
} format_type_t;

/*
 * cgraph API requires char * arguments instead of const char * in many
 * functions that do not modify them.
 */
#define	CGRAPH_NAME(x)	__DECONST(char *, std::string{x}.c_str())

static void
usage(void)
{

	fprintf(stderr, "usage: cpg-reducer [options] input-dot-file\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "-t path\t\t\tprefix to truncate in source code paths (default: none; e.g., /usr/src/sys/)\n");
	fprintf(stderr, "-n function|compartment\ttype of node (default: compartment)\n");
	fprintf(stderr, "-f d2|d3-arc\t\toutput format (default: d2)\n");
	exit(1);
}

static node_type_t
node_type_from_str(const char *str)
{

	if (strcmp(str, "function") == 0)
		return (NODE_TYPE_FUNCTION);
	else if (strcmp(str, "compartment") == 0)
		return (NODE_TYPE_COMPARTMENT);
	else
		return (NODE_TYPE_INVALID);
}

static format_type_t
format_type_from_str(const char *str)
{

	if (strcmp(str, "d2") == 0)
		return (FORMAT_TYPE_D2);
	else if (strcmp(str, "d3-arc") == 0)
		return (FORMAT_TYPE_D3_ARC);
	else
		return (FORMAT_TYPE_INVALID);
}

static std::string
node_name(const char *name, std::string prefix)
{
	std::string newname;

	newname = std::string{name};
	if (newname.length() == 0) {
		newname = std::string{"EMPTY"};
	} else {
		/*
		 * The label is empty or uses the format {FOO.c} where FOO
		 * consists of at least one character.
		 */
		assert(newname.length() >= 5);
		newname = newname.substr(1, newname.length() - 4);
		if (newname.compare(0, prefix.length(), prefix) == 0) {
			newname = newname.substr(prefix.length(), newname.length() - 1);
		}
	}
	return (newname);
}

static std::string
edge_name(const char *name)
{
	std::string newname;

	newname = std::string{name};
	assert(newname.length() > 2);
	newname = newname.substr(1, newname.length() - 2);
	return (newname);
}

static Agraph_t *
graph_create(Agraph_t *g, std::string prefix)
{
	Agraph_t *h;
	Agnode_t *n, *newn, *newm, *m, *nxtnode;
	Agedge_t *e, *nxtout;
	std::string file_n, file_m, label_m;

	h = agopen(CGRAPH_NAME("kernel"), Agdirected, NULL);
	assert(h != NULL);

	for (n = agfstnode(g); n != NULL; n = nxtnode) {
		nxtnode = agnxtnode(g, n);

		file_n = node_name(agget(n, CGRAPH_NAME("file")), prefix);

		newn = agnode(h, CGRAPH_NAME(file_n.c_str()), true);
		if (newn == NULL) {
			errx(1, "Unable to create a node with the name '%s'.\n",
			    file_n.c_str());
		}

		for (e = agfstout(g, n); e != NULL; e = nxtout) {
			nxtout = agnxtout(g, e);
			m = aghead(e);

			file_m = node_name(agget(m, CGRAPH_NAME("file")),
			    prefix);
			label_m = edge_name(agget(m, CGRAPH_NAME("label")));

			newm = agnode(h, CGRAPH_NAME(file_m.c_str()), true);
			if (newm == NULL) {
				errx(1, "Unable to create a node with the name '%s'.\n",
				    file_m.c_str());
			}
			if (!agedge(h, newn, newm, CGRAPH_NAME(label_m.c_str()),
			    true)) {
				errx(1, "Unable to create an edge %s-%s->%s.\n",
				    file_n.c_str(), label_m.c_str(),
				    file_m.c_str());
			}
		}
	}

	return (h);
}

static Agraph_t *
graph_remove_intra_edges(Agraph_t *g)
{
	Agnode_t *n, *nxtnode, *m;
	Agedge_t *e, *nxtout;
	std::string namen, namem;
	bool isreduced;

	for (n = agfstnode(g); n != NULL; n = nxtnode) {
		nxtnode = agnxtnode(g, n);
		isreduced = false;

		namen = std::string{agnameof(n)};

		for (e = agfstout(g, n); e != NULL; e = nxtout) {
			nxtout = agnxtout(g, e);
			m = aghead(e);

			namem = std::string{agnameof(m)};

			if (namen.compare("EMPTY") == 0 ||
			    namem.compare("EMPTY") == 0 ||
			    namen.compare(namem) != 0) {
				/*
				 * Leave the edge with at least one node not
				 * associated with any file or nodes associated
				 * with different files.
				 */
				continue;
			}

			/*
			 * Remove the edge if it's within the same file.
			 */
			agdelete(g, e);
			isreduced = true;

			if (agdegree(g, m, true, true) > 0) {
				/*
				 * Leave the adjacent node if it still has some
				 * edges.
				 */
				continue;
			}

			/*
			 * Remove the adjacent node if it doesn't have any more
			 * edges.
			 */
			if (nxtnode == m)
				nxtnode = agnxtnode(g, nxtnode);
			agdelnode(g, m);
		}

		if (isreduced && agdegree(g, n, true, true) == 0) {
			/*
			 * The node was reduced and doesn't have any inter-file
			 * edges.
			 *
			 * Nodes without edges that haven't been reduced are
			 * left in CPG to indicate potential issues with an
			 * input CPG.
			 */
			agdelnode(g, n);
		}
	}

	return (g);
}

static Agraph_t *
graph_merge_intra_nodes(Agraph_t *g)
{
	Agraph_t *h;
	Agnode_t *n, *newn, *newm, *m, *nxtnode;
	Agedge_t *e, *nxtout;
	std::string namee, namem, namen, value;

	h = agopen(CGRAPH_NAME("kernel"), Agdirected, NULL);
	assert(h != NULL);

	for (n = agfstnode(g); n != NULL; n = nxtnode) {
		std::map<std::string, std::vector<std::string>> targets;
		nxtnode = agnxtnode(g, n);

		newn = agnode(h, agnameof(n), true);
		assert(newn != NULL);

		for (e = agfstout(g, n); e != NULL; e = nxtout) {
			nxtout = agnxtout(g, e);
			m = aghead(e);

			newm = agnode(h, agnameof(m), true);
			assert(newm != NULL);
			namem = std::string{agnameof(newm)};
			value = std::string{agnameof(e)};

			if (targets.find(namem) == targets.end())
				targets.insert({namem, std::vector<std::string>()});
			auto it = targets.find(namem);
			it->second.push_back(value);
		}

		for (auto ii : targets) {
			namem = ii.first;
			newm = agnode(h, CGRAPH_NAME(namem.c_str()), false);
			assert(newm != NULL);

			sort(ii.second.begin(), ii.second.end());

			namee = "";
			for (auto it = ii.second.begin(); it != ii.second.end(); it++) {
				namee += *it;
				if (it + 1 != ii.second.end())
					namee += ",";
			}
			if (!agedge(h, newn, newm, CGRAPH_NAME(namee.c_str()),
			    true)) {
				errx(1, "Unable to create an edge %s-%s->%s.\n",
				    agnameof(newn), agnameof(newm),
				    namee.c_str());
			}
		}

		targets.clear();
	}

	agclose(g);
	return (h);
}

static void
graph_print_d2(Agraph_t *g)
{
	Agnode_t *n, *m, *nxtnode;
	Agedge_t *e, *nxtout;

	for (n = agfstnode(g); n != NULL; n = nxtnode) {
		nxtnode = agnxtnode(g, n);

		for (e = agfstout(g, n); e != NULL; e = nxtout) {
			nxtout = agnxtout(g, e);
			m = aghead(e);

			printf("%s -> %s: %s\n", agnameof(n), agnameof(m),
			    agnameof(e));
		}
	}
}

static void
graph_print_d3_arc(Agraph_t *g)
{
	Agnode_t *n, *m, *nxtnode;
	Agedge_t *e, *nxtout;
	std::string namen, namem, value;
	bool haslinks;

	printf("{\n");

	printf("  \"nodes\": [\n");
	for (n = agfstnode(g); n != NULL; n = nxtnode) {
		nxtnode = agnxtnode(g, n);

		namen = std::string{agnameof(n)};

		printf("    {\"id\": \"%s\", \"group\": \"%s\"}",
		    namen.c_str(), namen.c_str());
		if (nxtnode != NULL)
			printf(",");
		printf("\n");
	}
	printf("  ],\n");

	haslinks = false;
	printf("  \"links\": [\n");
	for (n = agfstnode(g); n != NULL; n = nxtnode) {
		nxtnode = agnxtnode(g, n);

		namen = std::string{agnameof(n)};

		for (e = agfstout(g, n); e != NULL; e = nxtout) {
			nxtout = agnxtout(g, e);
			m = aghead(e);

			namem = std::string{agnameof(m)};
			value = std::string{agnameof(e)};

			if (haslinks)
				printf(",\n");
			printf("    {\"source\": \"%s\", \"target\": \"%s\", \"value\": \"%s\"}",
			    namen.c_str(), namem.c_str(), value.c_str());
			haslinks = true;
		}
	}
	printf("\n");
	printf("  ]\n");

	printf("}\n");
}

int
main(int argc, char *argv[])
{
	GVC_t *gvc;
	Agraph_t *g, *reduced;
	char *gvargs[3];
	int ch;
	node_type_t nodetype;
	format_type_t formattype;
	std::string prefix;

	nodetype = NODE_TYPE_COMPARTMENT;
	formattype = FORMAT_TYPE_D2;

	while ((ch = getopt(argc, argv, "f:n:t:")) != -1) {
		switch (ch) {
		case 'n':
			nodetype = node_type_from_str(optarg);
			if (nodetype == NODE_TYPE_INVALID)
				usage();
			break;
		case 'f':
			formattype = format_type_from_str(optarg);
			if (formattype == FORMAT_TYPE_INVALID)
				usage();
			break;
		case 't':
			prefix = std::string{optarg};
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage();

	/* Set the layout engine to dot. */
	gvargs[0] = CGRAPH_NAME("dot");
	/* Parse the input file. */
	gvargs[1] = argv[0];
	gvargs[2] = NULL;

	gvc = gvContext();
	gvParseArgs(gvc, nitems(gvargs) - 1, gvargs);

	while ((g = gvNextInputGraph(gvc))) {
		reduced = graph_create(g, prefix);
		reduced = graph_remove_intra_edges(reduced);

		switch (nodetype) {
		case NODE_TYPE_COMPARTMENT:
			reduced = graph_merge_intra_nodes(reduced);
			break;
		default:
			/* Do nothing. */
			break;
		}

		switch (formattype) {
		case FORMAT_TYPE_D2:
			graph_print_d2(reduced);
			break;
		case FORMAT_TYPE_D3_ARC:
			graph_print_d3_arc(reduced);
			break;
		default:
			/* Do nothing. */
			break;
		}

		agclose(reduced);
	}

	(void)gvFreeContext(gvc);

	return (0);
}
