/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_DEVICE_OPERATIONS_H
#define OHOS_MEDIALIBRARY_DEVICE_OPERATIONS_H

#include <string>
#include <variant>
#include <grp.h>
#include <securec.h>
#include <stdlib.h>
#include <unistd.h>

#include "album_asset.h"
#include "data_ability_helper.h"
#include "device_manager.h"
#include "dm_device_info.h"
#include "media_data_ability_const.h"
#include "media_log.h"
#include "medialibrary_data_ability_utils.h"
#include "medialibrary_device_db.h"
#include "medialibrary_device_info.h"
#include "rdb_store.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
class MediaLibraryDeviceOperations {
public:
    MediaLibraryDeviceOperations();
    ~MediaLibraryDeviceOperations() {}

    bool InsertDeviceInfo(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                          const OHOS::Media::MediaLibraryDeviceInfo &deviceInfo, const std::string &bundleName);
    bool UpdateDeviceInfo(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                          const OHOS::Media::MediaLibraryDeviceInfo &deviceInfo, const std::string &bundleName);
    bool DeleteDeviceInfo(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &deviceId);
    bool UpdateSyncStatus(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &deviceId,
                          int32_t syncStatus, const std::string &bundleName);
    bool GetSyncStatusById(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &deviceId,
                           int32_t &syncStatus, const std::string &bundleName);
    bool QueryDeviceTable(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                          std::map<std::string, std::set<int>> &excludeMap);
    bool GetAllDeviceDatas(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                           vector<MediaLibraryDeviceInfo> &outDeviceList);
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_DEVICE_OPERATIONS_H