/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1991-1997 Søren Schmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <stdio.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/consio.h>
#include <sys/fbio.h>
#include "vgl.h"

#define BORDER	0xff	/* default border -- light white in rgb 3:3:2 */
#define INTERIOR 0xa0	/* default interior -- red in rgb 3:3:2 */
#define X	0xff	/* any nonzero in And mask means part of cursor */
#define B	BORDER
#define I	INTERIOR
static byte StdAndMask[MOUSE_IMG_SIZE*MOUSE_IMG_SIZE] = {
	X,X,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	X,X,X,0,0,0,0,0,0,0,0,0,0,0,0,0,
	X,X,X,X,0,0,0,0,0,0,0,0,0,0,0,0,
	X,X,X,X,X,0,0,0,0,0,0,0,0,0,0,0,
	X,X,X,X,X,X,0,0,0,0,0,0,0,0,0,0,
	X,X,X,X,X,X,X,0,0,0,0,0,0,0,0,0,
	X,X,X,X,X,X,X,X,0,0,0,0,0,0,0,0,
	X,X,X,X,X,X,X,X,X,0,0,0,0,0,0,0,
	X,X,X,X,X,X,X,X,X,X,0,0,0,0,0,0,
	X,X,X,X,X,X,X,X,X,X,0,0,0,0,0,0,
	X,X,X,X,X,X,X,0,0,0,0,0,0,0,0,0,
	X,X,X,0,X,X,X,X,0,0,0,0,0,0,0,0,
	X,X,0,0,X,X,X,X,0,0,0,0,0,0,0,0,
	0,0,0,0,0,X,X,X,X,0,0,0,0,0,0,0,
	0,0,0,0,0,X,X,X,X,0,0,0,0,0,0,0,
	0,0,0,0,0,0,X,X,0,0,0,0,0,0,0,0,
};
static byte StdOrMask[MOUSE_IMG_SIZE*MOUSE_IMG_SIZE] = {
	B,B,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	B,I,B,0,0,0,0,0,0,0,0,0,0,0,0,0,
	B,I,I,B,0,0,0,0,0,0,0,0,0,0,0,0,
	B,I,I,I,B,0,0,0,0,0,0,0,0,0,0,0,
	B,I,I,I,I,B,0,0,0,0,0,0,0,0,0,0,
	B,I,I,I,I,I,B,0,0,0,0,0,0,0,0,0,
	B,I,I,I,I,I,I,B,0,0,0,0,0,0,0,0,
	B,I,I,I,I,I,I,I,B,0,0,0,0,0,0,0,
	B,I,I,I,I,I,I,I,I,B,0,0,0,0,0,0,
	B,I,I,I,I,I,B,B,B,B,0,0,0,0,0,0,
	B,I,I,B,I,I,B,0,0,0,0,0,0,0,0,0,
	B,I,B,0,B,I,I,B,0,0,0,0,0,0,0,0,
	B,B,0,0,B,I,I,B,0,0,0,0,0,0,0,0,
	0,0,0,0,0,B,I,I,B,0,0,0,0,0,0,0,
	0,0,0,0,0,B,I,I,B,0,0,0,0,0,0,0,
	0,0,0,0,0,0,B,B,0,0,0,0,0,0,0,0,
};
#undef X
#undef B
#undef I
static VGLBitmap VGLMouseStdAndMask = 
    VGLBITMAP_INITIALIZER(MEMBUF, MOUSE_IMG_SIZE, MOUSE_IMG_SIZE, StdAndMask);
static VGLBitmap VGLMouseStdOrMask = 
    VGLBITMAP_INITIALIZER(MEMBUF, MOUSE_IMG_SIZE, MOUSE_IMG_SIZE, StdOrMask);
static VGLBitmap *VGLMouseAndMask, *VGLMouseOrMask;
static int VGLMouseVisible = 0;
static int VGLMouseShown = VGL_MOUSEHIDE;
static int VGLMouseXpos = 0;
static int VGLMouseYpos = 0;
static int VGLMouseButtons = 0;
static volatile sig_atomic_t VGLMintpending;
static volatile sig_atomic_t VGLMsuppressint;

#define	INTOFF()	(VGLMsuppressint++)
#define	INTON()		do { 						\
				if (--VGLMsuppressint == 0 && VGLMintpending) \
					VGLMouseAction(0);		\
			} while (0)

void
VGLMousePointerShow()
{
  if (!VGLMouseVisible) {
    INTOFF();
    VGLMouseVisible = 1;
    __VGLBitmapCopy(&VGLVDisplay, VGLMouseXpos, VGLMouseYpos, VGLDisplay, 
		  VGLMouseXpos, VGLMouseYpos, MOUSE_IMG_SIZE, -MOUSE_IMG_SIZE);
    INTON();
  }
}

void
VGLMousePointerHide()
{
  if (VGLMouseVisible) {
    INTOFF();
    VGLMouseVisible = 0;
    __VGLBitmapCopy(&VGLVDisplay, VGLMouseXpos, VGLMouseYpos, VGLDisplay, 
                    VGLMouseXpos, VGLMouseYpos, MOUSE_IMG_SIZE, MOUSE_IMG_SIZE);
    INTON();
  }
}

void
VGLMouseMode(int mode)
{
  if (mode == VGL_MOUSESHOW) {
    if (VGLMouseShown == VGL_MOUSEHIDE) {
      VGLMousePointerShow();
      VGLMouseShown = VGL_MOUSESHOW;
    }
  }
  else {
    if (VGLMouseShown == VGL_MOUSESHOW) {
      VGLMousePointerHide();
      VGLMouseShown = VGL_MOUSEHIDE;
    }
  }
}

void
VGLMouseAction(int dummy)	
{
  struct mouse_info mouseinfo;

  if (VGLMsuppressint) {
    VGLMintpending = 1;
    return;
  }
again:
  INTOFF();
  VGLMintpending = 0;
  mouseinfo.operation = MOUSE_GETINFO;
  ioctl(0, CONS_MOUSECTL, &mouseinfo);
  if (VGLMouseShown == VGL_MOUSESHOW)
    VGLMousePointerHide();
  VGLMouseXpos = mouseinfo.u.data.x;
  VGLMouseYpos = mouseinfo.u.data.y;
  VGLMouseButtons = mouseinfo.u.data.buttons;
  if (VGLMouseShown == VGL_MOUSESHOW)
    VGLMousePointerShow();

  /* 
   * Loop to handle any new (suppressed) signals.  This is INTON() without
   * recursion.  !SA_RESTART prevents recursion in signal handling.  So the
   * maximum recursion is 2 levels.
   */
  VGLMsuppressint = 0;
  if (VGLMintpending)
    goto again;
}

void
VGLMouseSetImage(VGLBitmap *AndMask, VGLBitmap *OrMask)
{
  if (VGLMouseShown == VGL_MOUSESHOW)
    VGLMousePointerHide();

  VGLMouseAndMask = AndMask;

  if (VGLMouseOrMask != NULL) {
    free(VGLMouseOrMask->Bitmap);
    free(VGLMouseOrMask);
  }
  VGLMouseOrMask = VGLBitmapCreate(MEMBUF, OrMask->VXsize, OrMask->VYsize, 0);
  VGLBitmapAllocateBits(VGLMouseOrMask);
  VGLBitmapCvt(OrMask, VGLMouseOrMask);

  if (VGLMouseShown == VGL_MOUSESHOW)
    VGLMousePointerShow();
}

void
VGLMouseSetStdImage()
{
  VGLMouseSetImage(&VGLMouseStdAndMask, &VGLMouseStdOrMask);
}

int
VGLMouseInit(int mode)
{
  struct mouse_info mouseinfo;
  int andmask, border, error, i, interior;

  switch (VGLModeInfo.vi_mem_model) {
  case V_INFO_MM_PACKED:
  case V_INFO_MM_PLANAR:
    andmask = 0x0f;
    border = 0x0f;
    interior = 0x04;
    break;
  case V_INFO_MM_VGAX:
    andmask = 0x3f;
    border = 0x3f;
    interior = 0x24;
    break;
  default:
    andmask = 0xff;
    border = BORDER;
    interior = INTERIOR;
    break;
  }
  if (VGLModeInfo.vi_mode == M_BG640x480)
    border = 0;		/* XXX (palette makes 0x04 look like 0x0f) */
  if (getenv("VGLMOUSEBORDERCOLOR") != NULL)
    border = strtoul(getenv("VGLMOUSEBORDERCOLOR"), NULL, 0);
  if (getenv("VGLMOUSEINTERIORCOLOR") != NULL)
    interior = strtoul(getenv("VGLMOUSEINTERIORCOLOR"), NULL, 0);
  for (i = 0; i < MOUSE_IMG_SIZE*MOUSE_IMG_SIZE; i++)
    VGLMouseStdOrMask.Bitmap[i] = VGLMouseStdOrMask.Bitmap[i] == BORDER ?
      border : VGLMouseStdOrMask.Bitmap[i] == INTERIOR ? interior : 0;
  VGLMouseSetStdImage();
  mouseinfo.operation = MOUSE_MODE;
  mouseinfo.u.mode.signal = SIGUSR2;
  if ((error = ioctl(0, CONS_MOUSECTL, &mouseinfo)))
    return error;
  signal(SIGUSR2, VGLMouseAction);
  mouseinfo.operation = MOUSE_GETINFO;
  ioctl(0, CONS_MOUSECTL, &mouseinfo);
  VGLMouseXpos = mouseinfo.u.data.x;
  VGLMouseYpos = mouseinfo.u.data.y;
  VGLMouseButtons = mouseinfo.u.data.buttons;
  VGLMouseMode(mode);
  return 0;
}

void
VGLMouseRestore(void)
{
  struct mouse_info mouseinfo;

  INTOFF();
  mouseinfo.operation = MOUSE_GETINFO;
  if (ioctl(0, CONS_MOUSECTL, &mouseinfo) == 0) {
    mouseinfo.operation = MOUSE_MOVEABS;
    mouseinfo.u.data.x = VGLMouseXpos;
    mouseinfo.u.data.y = VGLMouseYpos;
    ioctl(0, CONS_MOUSECTL, &mouseinfo);
  }
  INTON();
}

int
VGLMouseStatus(int *x, int *y, char *buttons)
{
  INTOFF();
  *x =  VGLMouseXpos;
  *y =  VGLMouseYpos;
  *buttons =  VGLMouseButtons;
  INTON();
  return VGLMouseShown;
}

void
VGLMouseFreeze(void)
{
  INTOFF();
}

int
VGLMouseFreezeXY(int x, int y)
{
  INTOFF();
  if (VGLMouseShown != VGL_MOUSESHOW)
    return 0;
  if (x >= VGLMouseXpos && x < VGLMouseXpos + MOUSE_IMG_SIZE &&
      y >= VGLMouseYpos && y < VGLMouseYpos + MOUSE_IMG_SIZE &&
      VGLMouseAndMask->Bitmap[(y-VGLMouseYpos)*MOUSE_IMG_SIZE+(x-VGLMouseXpos)])
    return 1;
  return 0;
}

int
VGLMouseOverlap(int x, int y, int width, int hight)
{
  int overlap;

  if (VGLMouseShown != VGL_MOUSESHOW)
    return 0;
  if (x > VGLMouseXpos)
    overlap = (VGLMouseXpos + MOUSE_IMG_SIZE) - x;
  else
    overlap = (x + width) - VGLMouseXpos;
  if (overlap <= 0)
    return 0;
  if (y > VGLMouseYpos)
    overlap = (VGLMouseYpos + MOUSE_IMG_SIZE) - y;
  else
    overlap = (y + hight) - VGLMouseYpos;
  return overlap > 0;
}

void
VGLMouseMerge(int x, int y, int width, byte *line)
{
  int pos, x1, xend, xstart;

  xstart = x;
  if (xstart < VGLMouseXpos)
    xstart = VGLMouseXpos;
  xend = x + width;
  if (xend > VGLMouseXpos + MOUSE_IMG_SIZE)
    xend = VGLMouseXpos + MOUSE_IMG_SIZE;
  for (x1 = xstart; x1 < xend; x1++) {
    pos = (y - VGLMouseYpos) * MOUSE_IMG_SIZE + x1 - VGLMouseXpos;
    if (VGLMouseAndMask->Bitmap[pos])
      bcopy(&VGLMouseOrMask->Bitmap[pos * VGLDisplay->PixelBytes],
            &line[(x1 - x) * VGLDisplay->PixelBytes], VGLDisplay->PixelBytes);
  }
}

void
VGLMouseUnFreeze()
{
  INTON();
}
