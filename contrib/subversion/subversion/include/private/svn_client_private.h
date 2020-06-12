/**
 * @copyright
 * ====================================================================
 *    Licensed to the Apache Software Foundation (ASF) under one
 *    or more contributor license agreements.  See the NOTICE file
 *    distributed with this work for additional information
 *    regarding copyright ownership.  The ASF licenses this file
 *    to you under the Apache License, Version 2.0 (the
 *    "License"); you may not use this file except in compliance
 *    with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing,
 *    software distributed under the License is distributed on an
 *    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *    KIND, either express or implied.  See the License for the
 *    specific language governing permissions and limitations
 *    under the License.
 * ====================================================================
 * @endcopyright
 *
 * @file svn_client_private.h
 * @brief Subversion-internal client APIs.
 */

#ifndef SVN_CLIENT_PRIVATE_H
#define SVN_CLIENT_PRIVATE_H

#include <apr_pools.h>

#include "svn_ra.h"
#include "svn_client.h"
#include "svn_types.h"

#include "private/svn_diff_tree.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/* Set *REVNUM to the revision number identified by REVISION.

   If REVISION->kind is svn_opt_revision_number, just use
   REVISION->value.number, ignoring LOCAL_ABSPATH and RA_SESSION.

   Else if REVISION->kind is svn_opt_revision_committed,
   svn_opt_revision_previous, or svn_opt_revision_base, or
   svn_opt_revision_working, then the revision can be identified
   purely based on the working copy's administrative information for
   LOCAL_ABSPATH, so RA_SESSION is ignored.  If LOCAL_ABSPATH is not
   under revision control, return SVN_ERR_UNVERSIONED_RESOURCE, or if
   LOCAL_ABSPATH is null, return SVN_ERR_CLIENT_VERSIONED_PATH_REQUIRED.

   Else if REVISION->kind is svn_opt_revision_date or
   svn_opt_revision_head, then RA_SESSION is used to retrieve the
   revision from the repository (using REVISION->value.date in the
   former case), and LOCAL_ABSPATH is ignored.  If RA_SESSION is null,
   return SVN_ERR_CLIENT_RA_ACCESS_REQUIRED.

   Else if REVISION->kind is svn_opt_revision_unspecified, set
   *REVNUM to SVN_INVALID_REVNUM.

   If YOUNGEST_REV is non-NULL, it is an in/out parameter.  If
   *YOUNGEST_REV is valid, use it as the youngest revision in the
   repository (regardless of reality) -- don't bother to lookup the
   true value for HEAD, and don't return any value in *REVNUM greater
   than *YOUNGEST_REV.  If *YOUNGEST_REV is not valid, and a HEAD
   lookup is required to populate *REVNUM, then also populate
   *YOUNGEST_REV with the result.  This is useful for making multiple
   serialized calls to this function with a basically static view of
   the repository, avoiding race conditions which could occur between
   multiple invocations with HEAD lookup requests.

   Else return SVN_ERR_CLIENT_BAD_REVISION.

   Use SCRATCH_POOL for any temporary allocation.  */
svn_error_t *
svn_client__get_revision_number(svn_revnum_t *revnum,
                                svn_revnum_t *youngest_rev,
                                svn_wc_context_t *wc_ctx,
                                const char *local_abspath,
                                svn_ra_session_t *ra_session,
                                const svn_opt_revision_t *revision,
                                apr_pool_t *scratch_pool);

/* Return true if KIND is a revision kind that is dependent on the working
 * copy. Otherwise, return false. */
#define SVN_CLIENT__REVKIND_NEEDS_WC(kind)                                 \
  ((kind) == svn_opt_revision_base ||                                      \
   (kind) == svn_opt_revision_previous ||                                  \
   (kind) == svn_opt_revision_working ||                                   \
   (kind) == svn_opt_revision_committed)                                   \

/* Return true if KIND is a revision kind that the WC can supply without
 * contacting the repository. Otherwise, return false. */
#define SVN_CLIENT__REVKIND_IS_LOCAL_TO_WC(kind)                           \
  ((kind) == svn_opt_revision_base ||                                      \
   (kind) == svn_opt_revision_working ||                                   \
   (kind) == svn_opt_revision_committed)

/* A location in a repository. */
typedef struct svn_client__pathrev_t
{
  const char *repos_root_url;
  const char *repos_uuid;
  svn_revnum_t rev;
  const char *url;
} svn_client__pathrev_t;

/* Return a new path-rev structure, allocated in RESULT_POOL,
 * initialized with deep copies of REPOS_ROOT_URL, REPOS_UUID, REV and URL. */
svn_client__pathrev_t *
svn_client__pathrev_create(const char *repos_root_url,
                           const char *repos_uuid,
                           svn_revnum_t rev,
                           const char *url,
                           apr_pool_t *result_pool);

/* Return a new path-rev structure, allocated in RESULT_POOL,
 * initialized with deep copies of REPOS_ROOT_URL, REPOS_UUID, and REV,
 * and using the repository-relative RELPATH to construct the URL. */
svn_client__pathrev_t *
svn_client__pathrev_create_with_relpath(const char *repos_root_url,
                                        const char *repos_uuid,
                                        svn_revnum_t rev,
                                        const char *relpath,
                                        apr_pool_t *result_pool);

/* Set *PATHREV_P to a new path-rev structure, allocated in RESULT_POOL,
 * initialized with deep copies of the repository root URL and UUID from
 * RA_SESSION, and of REV and URL. */
svn_error_t *
svn_client__pathrev_create_with_session(svn_client__pathrev_t **pathrev_p,
                                        svn_ra_session_t *ra_session,
                                        svn_revnum_t rev,
                                        const char *url,
                                        apr_pool_t *result_pool);

/* Return a deep copy of PATHREV, allocated in RESULT_POOL. */
svn_client__pathrev_t *
svn_client__pathrev_dup(const svn_client__pathrev_t *pathrev,
                        apr_pool_t *result_pool);

/* Return a deep copy of PATHREV, with a URI-encoded representation of
 * RELPATH joined on to the URL.  Allocate the result in RESULT_POOL. */
svn_client__pathrev_t *
svn_client__pathrev_join_relpath(const svn_client__pathrev_t *pathrev,
                                 const char *relpath,
                                 apr_pool_t *result_pool);

/* Return the repository-relative relpath of PATHREV. */
const char *
svn_client__pathrev_relpath(const svn_client__pathrev_t *pathrev,
                            apr_pool_t *result_pool);

/* Return the repository-relative fspath of PATHREV. */
const char *
svn_client__pathrev_fspath(const svn_client__pathrev_t *pathrev,
                           apr_pool_t *result_pool);

/* Given PATH_OR_URL, which contains either a working copy path or an
   absolute URL, a peg revision PEG_REVISION, and a desired revision
   REVISION, create an RA connection to that object as it exists in
   that revision, following copy history if necessary.  If REVISION is
   younger than PEG_REVISION, then PATH_OR_URL will be checked to see
   that it is the same node in both PEG_REVISION and REVISION.  If it
   is not, then @c SVN_ERR_CLIENT_UNRELATED_RESOURCES is returned.

   BASE_DIR_ABSPATH is the working copy path the ra_session corresponds
   to. If provided it will be used to read and dav props. So if provided
   this directory MUST match the session anchor.

   If PEG_REVISION->kind is 'unspecified', the peg revision is 'head'
   for a URL or 'working' for a WC path.  If REVISION->kind is
   'unspecified', the operative revision is the peg revision.

   Store the resulting ra_session in *RA_SESSION_P.  Store the final
   resolved location of the object in *RESOLVED_LOC_P.  RESOLVED_LOC_P
   may be NULL if not wanted.

   Use authentication baton cached in CTX to authenticate against the
   repository.

   Use POOL for all allocations. */
svn_error_t *
svn_client__ra_session_from_path2(svn_ra_session_t **ra_session_p,
                                 svn_client__pathrev_t **resolved_loc_p,
                                 const char *path_or_url,
                                 const char *base_dir_abspath,
                                 const svn_opt_revision_t *peg_revision,
                                 const svn_opt_revision_t *revision,
                                 svn_client_ctx_t *ctx,
                                 apr_pool_t *pool);

/* Given PATH_OR_URL, which contains either a working copy path or an
   absolute URL, a peg revision PEG_REVISION, and a desired revision
   REVISION, find the path at which that object exists in REVISION,
   following copy history if necessary.  If REVISION is younger than
   PEG_REVISION, then check that PATH_OR_URL is the same node in both
   PEG_REVISION and REVISION, and return @c
   SVN_ERR_CLIENT_UNRELATED_RESOURCES if it is not the same node.

   If PEG_REVISION->kind is 'unspecified', the peg revision is 'head'
   for a URL or 'working' for a WC path.  If REVISION->kind is
   'unspecified', the operative revision is the peg revision.

   Store the actual location of the object in *RESOLVED_LOC_P.

   RA_SESSION should be an open RA session pointing at the URL of
   PATH_OR_URL, or NULL, in which case this function will open its own
   temporary session.

   Use authentication baton cached in CTX to authenticate against the
   repository.

   Use POOL for all allocations. */
svn_error_t *
svn_client__resolve_rev_and_url(svn_client__pathrev_t **resolved_loc_p,
                                svn_ra_session_t *ra_session,
                                const char *path_or_url,
                                const svn_opt_revision_t *peg_revision,
                                const svn_opt_revision_t *revision,
                                svn_client_ctx_t *ctx,
                                apr_pool_t *pool);

/** Return @c SVN_ERR_ILLEGAL_TARGET if TARGETS contains a mixture of
 * URLs and paths; otherwise return SVN_NO_ERROR.
 *
 * @since New in 1.7.
 */
svn_error_t *
svn_client__assert_homogeneous_target_type(const apr_array_header_t *targets);


/* Create a svn_client_status_t structure *CST for LOCAL_ABSPATH, shallow
 * copying data from *STATUS wherever possible and retrieving the other values
 * where needed. Perform temporary allocations in SCRATCH_POOL and allocate the
 * result in RESULT_POOL
 */
svn_error_t *
svn_client__create_status(svn_client_status_t **cst,
                          svn_wc_context_t *wc_ctx,
                          const char *local_abspath,
                          const svn_wc_status3_t *status,
                          apr_pool_t *result_pool,
                          apr_pool_t *scratch_pool);

/* Get the repository location of the base node at LOCAL_ABSPATH.
 *
 * A pathrev_t wrapper around svn_wc__node_get_base().
 *
 * Set *BASE_P to the location that this node was checked out at or last
 * updated/switched to, regardless of any uncommitted changes (delete,
 * replace and/or copy-here/move-here).
 *
 * If there is no base node at LOCAL_ABSPATH (such as when there is a
 * locally added/copied/moved-here node that is not part of a replace),
 * set *BASE_P to NULL.
 */
svn_error_t *
svn_client__wc_node_get_base(svn_client__pathrev_t **base_p,
                             const char *wc_abspath,
                             svn_wc_context_t *wc_ctx,
                             apr_pool_t *result_pool,
                             apr_pool_t *scratch_pool);

/* Get the original location of the WC node at LOCAL_ABSPATH.
 *
 * A pathrev_t wrapper around svn_wc__node_get_origin().
 *
 * Set *ORIGIN_P to the origin of the WC node at WC_ABSPATH.  If the node
 * is a local copy, give the copy-from location.  If the node is locally
 * added or deleted, set *ORIGIN_P to NULL.
 */
svn_error_t *
svn_client__wc_node_get_origin(svn_client__pathrev_t **origin_p,
                               const char *wc_abspath,
                               svn_client_ctx_t *ctx,
                               apr_pool_t *result_pool,
                               apr_pool_t *scratch_pool);

/* Same as the public svn_client_mergeinfo_log2 API, except for the addition
 * of the TARGET_MERGEINFO_CATALOG and RESULT_POOL parameters.
 *
 * If TARGET_MERGEINFO_CATALOG is NULL then this acts exactly as the public
 * API.  If *TARGET_MERGEINFO_CATALOG is NULL, then *TARGET_MERGEINFO_CATALOG
 * is set to the a mergeinfo catalog representing the mergeinfo on
 * TARGET_PATH_OR_URL@TARGET_PEG_REVISION at DEPTH, (like the public API only
 * depths of svn_depth_empty or svn_depth_infinity are supported) allocated in
 * RESULT_POOL.  Finally, if *TARGET_MERGEINFO_CATALOG is non-NULL, then it is
 * assumed to be a mergeinfo catalog representing the mergeinfo on
 * TARGET_PATH_OR_URL@TARGET_PEG_REVISION at DEPTH.
 *
 * The keys for the subtree mergeinfo are the repository root-relative
 * paths of TARGET_PATH_OR_URL and/or its subtrees, regardless of whether
 * TARGET_PATH_OR_URL is a URL or WC path.
 *
 * If RA_SESSION is not NULL, use it to obtain merge information instead of
 * opening a new session. The session might be reparented after usage, so
 * callers should reparent the session back to their original location if
 * needed.
 */
svn_error_t *
svn_client__mergeinfo_log(svn_boolean_t finding_merged,
                          const char *target_path_or_url,
                          const svn_opt_revision_t *target_peg_revision,
                          svn_mergeinfo_catalog_t *target_mergeinfo_catalog,
                          const char *source_path_or_url,
                          const svn_opt_revision_t *source_peg_revision,
                          const svn_opt_revision_t *source_start_revision,
                          const svn_opt_revision_t *source_end_revision,
                          svn_log_entry_receiver_t log_receiver,
                          void *log_receiver_baton,
                          svn_boolean_t discover_changed_paths,
                          svn_depth_t depth,
                          const apr_array_header_t *revprops,
                          svn_client_ctx_t *ctx,
                          svn_ra_session_t *ra_session,
                          apr_pool_t *result_pool,
                          apr_pool_t *scratch_pool);

/** Return a diff processor that will print a Subversion-style
 * (not git-style) diff.
 *
 * @a anchor is optional (may be null), and is the 'anchor' path to prefix
 * to the diff-processor paths before displaying.
 *
 * @a orig_path_1 and @a orig_path_2 are the two main root paths to be
 * diffed; each may be a URL, a local WC path or a local unversioned path.
 *
 * Other arguments are as for svn_client_diff7() etc.
 */
svn_error_t *
svn_client__get_diff_writer_svn(
                svn_diff_tree_processor_t **diff_processor,
                const char *anchor,
                const char *orig_path_1,
                const char *orig_path_2,
                const apr_array_header_t *options,
                const char *relative_to_dir,
                svn_boolean_t no_diff_added,
                svn_boolean_t no_diff_deleted,
                svn_boolean_t show_copies_as_adds,
                svn_boolean_t ignore_content_type,
                svn_boolean_t ignore_properties,
                svn_boolean_t properties_only,
                svn_boolean_t pretty_print_mergeinfo,
                const char *header_encoding,
                svn_stream_t *outstream,
                svn_stream_t *errstream,
                svn_client_ctx_t *ctx,
                apr_pool_t *pool);

/*** Editor for diff summary ***/

/* Set *DIFF_PROCESSOR to a diff processor that will report a diff summary
   to SUMMARIZE_FUNC.

   SUMMARIZE_FUNC is called with SUMMARIZE_BATON as parameter by the
   created callbacks for each changed item.
*/
svn_error_t *
svn_client__get_diff_summarize_callbacks(
                        svn_diff_tree_processor_t **diff_processor,
                        svn_client_diff_summarize_func_t summarize_func,
                        void *summarize_baton,
                        apr_pool_t *result_pool,
                        apr_pool_t *scratch_pool);

/** Copy a directory tree or a file (according to @a kind) from @a src_url at
 * @a src_rev, to @a dst_abspath in a WC.
 *
 * The caller should be holding a WC write lock that allows @a dst_abspath to
 * be created, such as on the parent of @a dst_abspath.
 *
 * If not same repositories, then remove any svn:mergeinfo property.
 *
 * Use @a ra_session to fetch the data. The session may point to any URL
 * within the source repository.
 *
 * This API does not process any externals definitions that may be present
 * on copied directories.
 */
svn_error_t *
svn_client__repos_to_wc_copy_internal(svn_boolean_t *timestamp_sleep,
                             svn_node_kind_t kind,
                             const char *src_url,
                             svn_revnum_t src_rev,
                             const char *dst_abspath,
                             svn_ra_session_t *ra_session,
                             svn_client_ctx_t *ctx,
                             apr_pool_t *scratch_pool);

/** Copy a directory tree or a file (according to @a kind) from @a src_url at
 * @a src_rev, to @a dst_abspath in a WC.
 *
 * The caller should be holding a WC write lock that allows @a dst_abspath to
 * be created, such as on the parent of @a dst_abspath.
 *
 * If not same repositories, then remove any svn:mergeinfo property.
 *
 * Use @a ra_session to fetch the data. The session may point to a different
 * URL after returning.
 *
 * This API does not process any externals definitions that may be present
 * on copied directories.
 */
svn_error_t *
svn_client__repos_to_wc_copy_by_editor(svn_boolean_t *timestamp_sleep,
                svn_node_kind_t kind,
                const char *src_url,
                svn_revnum_t src_rev,
                const char *dst_abspath,
                svn_ra_session_t *ra_session,
                svn_client_ctx_t *ctx,
                apr_pool_t *scratch_pool);

/** Return an editor for applying local modifications to a WC.
 *
 * Return an editor in @a *editor_p, @a *edit_baton_p that will apply
 * local modifications to the WC subdirectory at @a dst_abspath.
 *
 * The @a path arguments to the editor methods shall be local WC paths,
 * relative to @a dst_abspath. The @a copyfrom_path arguments to the
 * editor methods shall be URLs.
 *
 * Send notifications via @a notify_func / @a notify_baton.
 * ### INCOMPLETE
 *
 * @a ra_session is used to fetch the original content for copies.
 *
 * Ignore changes to non-regular property (entry-props, DAV/WC-props).
 *
 * Acquire the WC write lock in 'open_root' and release it in
 * 'close_edit', in 'abort_edit', or when @a result_pool is cleared.
 */
svn_error_t *
svn_client__wc_editor(const svn_delta_editor_t **editor_p,
                      void **edit_baton_p,
                      const char *dst_abspath,
                      svn_wc_notify_func2_t notify_func,
                      void *notify_baton,
                      svn_ra_session_t *ra_session,
                      svn_client_ctx_t *ctx,
                      apr_pool_t *result_pool);

/* Return an editor for applying local modifications to a WC.
 *
 * Like svn_client__wc_editor() but with additional options.
 *
 * If @a root_dir_add is true, then create and schedule for addition
 * the root directory of this edit, else assume it is already a versioned,
 * existing directory.
 *
 * If @a ignore_mergeinfo_changes is true, ignore any incoming changes
 * to the 'svn:mergeinfo' property.
 *
 * If @a manage_wc_write_lock is true, acquire the WC write lock in
 * 'open_root' and release it in 'close_edit', in 'abort_edit', or
 * when @a result_pool is cleared.
 */
svn_error_t *
svn_client__wc_editor_internal(const svn_delta_editor_t **editor_p,
                               void **edit_baton_p,
                               const char *dst_abspath,
                               svn_boolean_t root_dir_add,
                               svn_boolean_t ignore_mergeinfo_changes,
                               svn_boolean_t manage_wc_write_lock,
                               svn_wc_notify_func2_t notify_func,
                               void *notify_baton,
                               svn_ra_session_t *ra_session,
                               svn_client_ctx_t *ctx,
                               apr_pool_t *result_pool);

/** Send committable changes found in the WC to a delta-editor.
 *
 * Committable changes are found in TARGETS:DEPTH:CHANGELISTS.
 *
 * Send the changes to @a editor:@a edit_baton. The @a path arguments
 * to the editor methods are URL-paths relative to the URL of
 * @a src_wc_abspath.
 *
 *    ### We will presumably need to change this so that the @a path
 *        arguments to the editor will be local WC relpaths, in order
 *        to handle switched paths.
 *
 * The @a copyfrom_path arguments to the editor methods are URLs. As the
 * WC does not store copied-from-foreign-repository metadata, the URL will
 * be in the same repository as the URL of its parent path.
 *
 * Compared with svn_client__do_commit(), this (like svn_client_commit6)
 * handles:
 *  - condense targets and find committable paths
 *  - checking only one repository is involved
 *
 * Compared with svn_client_commit6(), this does not handle:
 *  - externals
 *  - log message
 *  - revprops
 *  - checking the commit includes both halves of each local move
 *  - changing the copy revision of each local move to ~HEAD
 *  - WC write locks
 *  - bumping revisions in WC
 *  - removing locks and changelists in WC
 */
svn_error_t *
svn_client__wc_replay(const char *src_wc_abspath,
                      const apr_array_header_t *targets,
                      svn_depth_t depth,
                      const apr_array_header_t *changelists,
                      const svn_delta_editor_t *editor,
                      void *edit_baton,
                      svn_wc_notify_func2_t notify_func,
                      void *notify_baton,
                      svn_client_ctx_t *ctx,
                      apr_pool_t *scratch_pool);

/** Copy local modifications from one WC subtree to another.
 *
 * Find local modifications under @a src_wc_abspath, in the same way as
 * for a commit.
 *
 * Edit the WC at @a dst_wc_abspath, applying those modifications to the
 * current working state to produce a new working state.
 *
 * The source and destination may be in the same WC or in different WCs.
 */
svn_error_t *
svn_client__wc_copy_mods(const char *src_wc_abspath,
                         const char *dst_wc_abspath,
                         svn_wc_notify_func2_t notify_func,
                         void *notify_baton,
                         svn_client_ctx_t *ctx,
                         apr_pool_t *scratch_pool);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SVN_CLIENT_PRIVATE_H */
