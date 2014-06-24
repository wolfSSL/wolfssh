/* ssh.c 
 *
 * Copyright (C) 2014 wolfSSL Inc.
 *
 * This file is part of wolfSSH.
 *
 * wolfSSH is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSH is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/log.h>


int wolfSSH_Init(void)
{
    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_Init()");
    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_Init(), returning %d", WS_SUCCESS);
    return WS_SUCCESS;
}


int wolfSSH_Cleanup(void)
{
    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_Cleanup()");
    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_Cleanup(), returning %d", WS_SUCCESS);
    return WS_SUCCESS;
}

