/*
 * Copyright (c) 2017 IETF Trust and the persons identified
 * as authors of the code.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with
 * or without modification, are permitted provided that the
 * following conditions are met:
 *
 * o Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer in the documentation and/or other
 *   materials provided with the distribution.
 *
 * o Neither the name of Internet Society, IETF or IETF
 *   Trust, nor the names of specific contributors, may be
 *   used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS
 *   AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 *   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *   FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
 *   EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *   NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 *   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *   ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This code was derived from RFC 8276.
 * Please reproduce this note if possible.
 */
/*
 * xattr_prot.x
 */
/*
 * The following includes statements that are for example only.
 * The actual XDR definition files are generated separately
 * and independently and are likely to have a different name.
 * %#include <rpc_prot.x>
 * %#include <nfsv42.x>
 */
typedef component4     xattrkey4;
typedef opaque         xattrvalue4<>;
/* Following lines are to be added to enum nfsstat4 */
/*
* NFS4ERR_NOXATTR        = 10095,
* NFS4ERR_XATTR2BIG      = 10096
*/
struct GETXATTR4args {
        /* CURRENT_FH: file */
        xattrkey4     gxa_name;
};
union GETXATTR4res switch (nfsstat4 gxr_status) {
 case NFS4_OK:
        xattrvalue4   gxr_value;
 default:
        void;
};
enum setxattr_option4 {
        SETXATTR4_EITHER      = 0,
        SETXATTR4_CREATE      = 1,
        SETXATTR4_REPLACE     = 2
};
struct SETXATTR4args {
        /* CURRENT_FH: file */
        setxattr_option4 sxa_option;
        xattrkey4        sxa_key;
        xattrvalue4      sxa_value;
};
union SETXATTR4res switch (nfsstat4 sxr_status) {
 case NFS4_OK:
        change_info4      sxr_info;
 default:
        void;
};
struct LISTXATTRS4args {
        /* CURRENT_FH: file */
        nfs_cookie4    lxa_cookie;
        count4         lxa_maxcount;
};
struct LISTXATTRS4resok {
        nfs_cookie4    lxr_cookie;
        xattrkey4      lxr_names<>;
        bool           lxr_eof;
};
union LISTXATTRS4res switch (nfsstat4 lxr_status) {
 case NFS4_OK:
        LISTXATTRS4resok  lxr_value;
 default:
        void;
};
struct REMOVEXATTR4args {
        /* CURRENT_FH: file */
        xattrkey4      rxa_name;
};
union REMOVEXATTR4res switch (nfsstat4 rxr_status) {
 case NFS4_OK:
        change_info4      rxr_info;
 default:
        void;
};
/*
 * ACCESS - Check Access Rights
 */
const ACCESS4_XAREAD    = 0x00000040;
const ACCESS4_XAWRITE   = 0x00000080;
const ACCESS4_XALIST    = 0x00000100;
/*
 * New NFSv4 attribute
 */
typedef bool            fattr4_xattr_support;
/*
 * New RECOMMENDED Attribute
 */
const FATTR4_XATTR_SUPPORT = 82;

/*
 * According to rfc8276, below changes have been added to
 * corresponding structures in "nfs4_prot.x" so they can be
 * auto-generated as a part of the overall AWS File Service
 * protocol ("awsfile_prot.x")
 */

/* Following lines are to be added to enum nfs_opnum4 */
/*
 * OP_GETXATTR                = 72,
 * OP_SETXATTR                = 73,
 * OP_LISTXATTRS              = 74,
 * OP_REMOVEXATTR             = 75,
*/
/*
 * New cases for Operation arrays
 */
/* Following lines are to be added to nfs_argop4 */
/*
 * case OP_GETXATTR:      GETXATTR4args opgetxattr;
 * case OP_SETXATTR:      SETXATTR4args opsetxattr;
 * case OP_LISTXATTRS:    LISTXATTRS4args oplistxattrs;
 * case OP_REMOVEXATTR:   REMOVEXATTR4args opremovexattr;
*/
/* Following lines are to be added to nfs_resop4 */
/*
 * case OP_GETXATTR:      GETXATTR4res opgetxattr;
 * case OP_SETXATTR:      SETXATTR4res opsetxattr;
 * case OP_LISTXATTRS:    LISTXATTRS4res oplistxattrs;
 * case OP_REMOVEXATTR:   REMOVEXATTR4res opremovexattr;
*/
