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

#ifndef OHOS_FILEMANAGEMENT_HMDFS_H
#define OHOS_FILEMANAGEMENT_HMDFS_H

#include <cstdint>
#include <sys/ioctl.h>

namespace OHOS {
namespace Media {
constexpr unsigned HMDFS_IOC = 0xf2;
constexpr unsigned GETCALLER_CMD = 0x05;

static const unsigned int MAX_BUNDLE_NAME_LEN = 64;

struct HmdfsCallerInfo {
    uint32_t tokenId;
    char bundleName[MAX_BUNDLE_NAME_LEN];
};

#define HMDFS_IOC_GET_CALLER_INFO _IOW(HMDFS_IOC, GETCALLER_CMD, struct HmdfsCallerInfo)
} // namespace Media
} // namespace OHOS
#endif // OHOS_FILEMANAGEMENT_HMDFS_H