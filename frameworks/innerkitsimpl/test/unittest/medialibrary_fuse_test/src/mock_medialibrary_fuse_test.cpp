/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define FUSE_USE_VERSION 34
#include <fuse.h>
#include "fuse_common.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/uio.h>
#include "fuse_config.h"
#include "fuse_i.h"
#include "fuse_lowlevel.h"
#include "media_log.h"

static constexpr int32_t UID = 60000;

struct fuse_context_i {
    struct fuse_context ctx;
    fuse_req_t req;
};

struct fuse_context *fuse_get_context(void)
{
    MEDIA_INFO_LOG("run mock_fuse_get_context");
    static struct fuse_context_i c ;
    c.ctx.uid = UID;
    return &c.ctx;
}
