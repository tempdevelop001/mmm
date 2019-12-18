/*-
 * Copyright 2013-2018 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "yespower.h"

int verstring;

int scanhash_yespower(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
        uint32_t max_nonce, unsigned long *hashes_done, int perslen, int verstring)
{
        uint32_t n = pdata[19] - 1;
        const uint32_t first_nonce = pdata[19];

        uint32_t hash64[8] __attribute__((aligned(32)));
        uint32_t endiandata[32];
	 if (verstring==1)
    {
    //puts("1111111");
	static const yespower_params_t params = {
		.version = YESPOWER_1_0,
		.N = 2048,
		.r = 32,
		.pers = NULL,
		.perslen = 0
	};
    }
	 if (verstring==2)
    {
    //puts("22222222");
	static const yespower_params_t params = {
		.version = YESPOWER_1_0,
		.N = 4096,
		.r = 16,
		.pers = NULL,
		.perslen = 0
	};
    }

	 if (verstring==3)
    {
	static const yespower_params_t params = {
		.version = YESPOWER_1_0,
		.N = 2048,
		.r = 32,
		.pers = (const uint8_t *)"UraniumX",
		.perslen = 8
	};
    }	
	 if (verstring==4)
    {
	static const yespower_params_t params = {
		.version = YESPOWER_1_0,
		.N = 2048,
		.r = 32,
		.pers = "CPUpower: The number of CPU working or available for proof-of-work mining",
		.perslen = 73
	};
    }
	 if (verstring==5)
    {
	static const yespower_params_t params = {
		.version = YESPOWER_1_0,
		.N = 4096,
		.r = 32,
		.pers = NULL,
		.perslen = 0
	};
    }		    		
	 if (verstring==6)
    {
	yespower_params_t params = {
		.version = YESPOWER_0_5,
		.N = 2048,
		.r = 8,
		.pers = (const uint8_t *)endiandata,
		.perslen = perslen
	};
    }		    		

/*    
    static const yespower_params_t v2 = {YESPOWER_1_0, 4096, 16, NULL, 0};
    
    yespower_params_t params = v2;
*/    
    
    
/*
	yespower_params_t params = {
	.version = YESPOWER_1_0,
	.N = 4096,
	.r = 16,
	.pers = NULL,
	.perslen = 0
    };
*/
    
        //we need bigendian data...
        int kk=0;
        for (; kk < 32; kk++)
        {
                be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
        };

        do {
                pdata[19] = ++n;
                be32enc(&endiandata[19], n);
		if (verstring==1) {
		    static const yespower_params_t v1 = {YESPOWER_1_0, 2048, 32, NULL, 0};
		    if (yespower_tls((unsigned char *)endiandata, perslen, &v1, (yespower_binary_t *)hash64)) {
		        puts("FAILED");
		        return -1;
		    }
		}
		if (verstring==2) {
		    static const yespower_params_t v2 = {YESPOWER_1_0, 4096, 16, NULL, 0};
		    if (yespower_tls((unsigned char *)endiandata, perslen, &v2, (yespower_binary_t *)hash64)) {
		        puts("FAILED");
		        return -1;
		    }
		}    
		if (verstring==3) {
		    static const yespower_params_t v3 = {YESPOWER_1_0, 2048, 32, (const uint8_t *)"UraniumX", 8};
		    if (yespower_tls((unsigned char *)endiandata, perslen, &v3, (yespower_binary_t *)hash64)) {
		        puts("FAILED");
		        return -1;
		    }
		}
		if (verstring==4) {
		    static const yespower_params_t v4 = {YESPOWER_1_0, 2048, 32, "CPUpower: The number of CPU working or available for proof-of-work mining", 73};
		    if (yespower_tls((unsigned char *)endiandata, perslen, &v4, (yespower_binary_t *)hash64)) {
		        puts("FAILED");
		        return -1;
		    }
		}
		if (verstring==5) {
		    static const yespower_params_t v5 = {YESPOWER_1_0, 4096, 32, NULL, 0};
		    if (yespower_tls((unsigned char *)endiandata, perslen, &v5, (yespower_binary_t *)hash64)) {
		        puts("FAILED");
		        return -1;
		    }
		}  
		if (verstring==6) {
		    yespower_params_t v6 = {YESPOWER_0_5, 2048, 8, (const uint8_t *)endiandata, perslen};
		    if (yespower_tls((unsigned char *)endiandata, perslen, &v6, (yespower_binary_t *)hash64)) {
		        puts("FAILED");
		        return -1;
		    }
		}       		
                if ((hash64[7] < ptarget[7]) || ((hash64[7] == ptarget[7]) && (hash64[6] < ptarget[6])) && fulltest(hash64, ptarget)) {
                        *hashes_done = n - first_nonce + 1;
                        return true;
                }
        } while (n < max_nonce && !work_restart[thr_id].restart);

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;
        return 0;
}
