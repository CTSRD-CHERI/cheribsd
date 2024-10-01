/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Konrad Witaszczyk
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. FA8750-24-C-B047 ("DEC").
 */

#ifndef _SIFT_SA_H_
#define	_SIFT_SA_H_

#define	BUFFER_SIZE	16

struct sift_sa_data {
	char buffer[BUFFER_SIZE];
	size_t size;
};

#endif /* !_SIFT_SA_H_ */
