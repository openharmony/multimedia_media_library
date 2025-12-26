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
#define RESTORE_MAP_LOG_TAG "RestoreMapCode"

#include "restore_map_code_utils.h"
#include "media_column.h"
#include "photo_map_code_operation.h"

#include "medialibrary_rdbstore.h"
#include "directory_ex.h"
#include "media_log.h"
#include "medialibrary_type_const.h"

#include "application_context.h"
#include "backup_database_utils.h"
#include "backup_dfx_utils.h"
#include "backup_file_utils.h"
#include "backup_log_utils.h"
#include "cloud_sync_manager.h"
#include "cloud_sync_utils.h"
#include "directory_ex.h"
#include "extension_context.h"
#include "media_log.h"
#include "media_file_utils.h"
#include "media_scanner_manager.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_type_const.h"
#include "medialibrary_errno.h"
#include "moving_photo_file_utils.h"
#include <nlohmann/json.hpp>
#include "parameters.h"
#include "photo_album_column.h"
#include "result_set_utils.h"
#include "userfilemgr_uri.h"
#include "medialibrary_notify.h"
#include "upgrade_restore_task_report.h"
#include "medialibrary_rdb_transaction.h"
#include "database_report.h"
#include "ohos_account_kits.h"

#include <cerrno>
#include <fstream>
#include <iostream>
#include <bitset>
#include <string>
#include <cmath>

namespace OHOS {
namespace Media {
using namespace std;
static constexpr double DOUBLE_EPSILON = 1e-15;
static constexpr double MAX_LATITUDE_EPSILON = 1e-15 + 90.0;
static constexpr double MAX_LONGITUDE_EPSILON = 1e-15 + 180.0;

int32_t RestoreMapCodeUtils::FileInfosToMapCode(const std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb,
    const vector<FileInfo> &fileInfos)
{
    MEDIA_DEBUG_LOG("RestoreMapCodeUtils::FileInfosToMapCode fileInfos size %{public}zu", fileInfos.size());
    vector<PhotoMapData> photoMapDatas;
    int64_t rowNum = 0;
    for (const auto &fileInfo : fileInfos) {
        double longitude = fileInfo.longitude;
        double latitude = fileInfo.latitude;
        int32_t fileId = fileInfo.fileIdNew;
        if (fileId > 0 && fabs(longitude) > DOUBLE_EPSILON && fabs(latitude) > DOUBLE_EPSILON &&
            fabs(longitude) < MAX_LONGITUDE_EPSILON && fabs(latitude) < MAX_LATITUDE_EPSILON) {
            PhotoMapData photoMapData(fileId, latitude, longitude);
            photoMapDatas.emplace_back(photoMapData);
        }
    }

    return PhotoMapCodeOperation::InsertPhotosMapCodes(photoMapDatas, mediaLibraryRdb);
}

int32_t RestoreMapCodeUtils::FileInfoToMapCode(const FileInfo &fileInfo,
    const std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb)
{
    MEDIA_DEBUG_LOG("RestoreMapCodeUtils::FileInfoToMapCode");
    vector<PhotoMapData> photoMapDatas;
    int64_t rowNum = 0;
    double longitude = fileInfo.longitude;
    double latitude = fileInfo.latitude;
    int32_t fileId = fileInfo.fileIdNew;
    if (fileId > 0 && fabs(longitude) > DOUBLE_EPSILON && fabs(latitude) > DOUBLE_EPSILON &&
        fabs(longitude) < MAX_LONGITUDE_EPSILON && fabs(latitude) < MAX_LATITUDE_EPSILON) {
        PhotoMapData photoMapData(fileId, latitude, longitude);
        photoMapDatas.emplace_back(photoMapData);
    }

    return PhotoMapCodeOperation::InsertPhotosMapCodes(photoMapDatas, mediaLibraryRdb);
}

int64_t RestoreMapCodeUtils::DeleteMapCodesByFileIds(const vector<string> &fileIds)
{
    return PhotoMapCodeOperation::RemovePhotosMapCodes(fileIds);
}
} // namespace Media
} // namespace OHOS
