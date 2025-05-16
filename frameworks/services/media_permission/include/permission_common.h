/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef PERMISSION_COMMON_H
#define PERMISSION_COMMON_H

#include "medialibrary_command.h"
#include "media_log.h"
#include "medialibrary_errno.h"

namespace OHOS::Media {

static const std::string FIELD_PERMISSION_TYPE = "permission_type";

static const std::string TABLE_PERMISSION = "UriPermission"; // 权限表

static const int32_t GRANT_PERMISSION_CALLING_UID = 5523; // foundation调用方
static const int32_t ROOT_UID = 0;
static const int32_t SANDBOX_UID = 3076;

/**
 * 鉴权参数
 */
struct PermParam {
    bool isWrite = false; // true-鉴权写权限，false-鉴权读权限
    bool isOpenFile = false; // 是否OpenFile接口鉴权
    std::string openFileNode = ""; // isOpenFile=true时使用，文件模式的含义
};

/**
 * 获取客户端appId
 */
std::string GetClientAppId();

/**
 * 是否需要鉴权Mediatool
 */
bool IsMediatoolOperation(MediaLibraryCommand &cmd);

/**
 * 是否是DeveloperMediaTool
 */
bool IsDeveloperMediaTool(MediaLibraryCommand &cmd, const std::string &openFileMode = "");

/**
 * 转换鉴权结果
 */
int32_t ConvertPermResult(bool isPermSuccess);

} // namespace OHOS::Media

#endif