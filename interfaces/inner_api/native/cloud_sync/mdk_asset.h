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
#ifndef OHOS_MEDIA_CLOUD_SYNC_ASSET_H
#define OHOS_MEDIA_CLOUD_SYNC_ASSET_H

#include <string>
#include <limits>

#define EXPORT __attribute__ ((visibility ("default")))

namespace OHOS::Media::CloudSync {
enum class MDKAssetOperType {
    DK_ASSET_NONE = 0,  // Asset无修改，云端上传时不上传
    DK_ASSET_ADD,
    DK_ASSET_UPDATE,
    DK_ASSET_DELETE,
    DK_ASSET_MAX,
};
constexpr uint64_t M_INVAILD_FILE_SIZE = std::numeric_limits<uint64_t>::max();
struct MDKAsset {
    std::string uri;
    std::string assetName;
    MDKAssetOperType operationType;
    std::string hash; // 文件sha256信息
    int64_t version; // asset的版本
    std::string assetId;
    std::string subPath; // 应用分布式目录下的相对路径
    std::string exCheckInfo; // 扩展字段，端侧可以用该值做文件校验
    uint64_t size = M_INVAILD_FILE_SIZE; // 资产大小
    int fd; // 待上传附件的fd
};
}  // namespace OHOS::Media::CloudSync
#endif