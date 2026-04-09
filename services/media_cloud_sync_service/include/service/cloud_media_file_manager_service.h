/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_FILE_MANAGER_SERVICE_H
#define OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_FILE_MANAGER_SERVICE_H

#include <string>

#include "cloud_media_define.h"
#include "cloud_media_pull_data_dto.h"
#include "photos_po.h"
#include "cloud_media_common_dao.h"
#include "cloud_media_file_info_service.h"

namespace OHOS::Media::CloudSync {
using namespace OHOS::Media::ORM;
class EXPORT CloudMediaFileManagerService {
public:
    void FixFileInfo(CloudMediaPullDataDto &pullData);
    int32_t RelocateFile(CloudMediaPullDataDto &pullData);

private:
    bool Accept(CloudMediaPullDataDto &pullData);

private:
    CloudMediaFileInfoService fileInfoService_;
    CloudMediaCommonDao commonDao_;
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_FILE_MANAGER_SERVICE_H