/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_CLOUD_DOWNLOAD_THUM_PARA_H
#define OHOS_MEDIA_CLOUD_DOWNLOAD_THUM_PARA_H

#include <string>
#include <map>
#include <sstream>

#include "cloud_file_data.h"

namespace OHOS::Media::CloudSync {
#define EXPORT __attribute__ ((visibility ("default")))
// 缩略图下载传入条件参数
struct DownloadThumPara {
    int32_t size;     // 设置查询个数
    int32_t offset;   // 设置查询偏移
    int32_t type;     // 设置查询类型（thum、lcd或both）
    bool isDownloadDisplayFirst;  // 是否按照图库展示优先下载
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_DOWNLOAD_THUM_PARA_H