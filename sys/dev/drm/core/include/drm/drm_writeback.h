/* Public domain. */

struct drm_writeback_job {
	struct dma_fence *out_fence;
	struct drm_framebuffer *fb;
};

struct drm_writeback_connector;

static inline struct drm_writeback_connector *
drm_connector_to_writeback(struct drm_connector *conn)
{

	return (NULL);
}

static inline struct dma_fence *
drm_writeback_get_out_fence(struct drm_writeback_connector *wb_connector)
{

	return (NULL);
}

#define	drm_writeback_prepare_job(wb)	0
#define	drm_writeback_cleanup_job(wb)
#define	drm_writeback_set_fb(conn, fb)	0
