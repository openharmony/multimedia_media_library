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
#define SCANNER_MAP_LOG_TAG "ScannerMapCode"

#include "scanner_map_code_utils.h"
#include "media_column.h"
#include "photo_map_code_column.h"
#include "photo_map_code_operation.h"

#include "medialibrary_rdbstore.h"
#include "directory_ex.h"
#include "media_log.h"
#include "medialibrary_type_const.h"
#include "medialibrary_unistore_manager.h"
#include "values_bucket.h"
#include "post_event_utils.h"
#include "abs_rdb_predicates.h"
#include "media_scanner_db.h"
#include "ipc_skeleton.h"
#include "medialibrary_asset_operations.h"
#include "media_error_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdb_transaction.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_smartalbum_map_operations.h"
#include "rdb_errno.h"
#include "rdb_utils.h"
#include "result_set.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"
#include "userfilemgr_uri.h"
#include "values_bucket.h"
#include "post_event_utils.h"

#include <cerrno>
#include <fstream>
#include <iostream>
#include <bitset>
#include <string>
#include <cmath>
#include <cctype>

namespace OHOS {
namespace Media {
using namespace std;
static constexpr double DOUBLE_EPSILON = 1e-15;
static constexpr double MAX_LATITUDE_EPSILON = 1e-15 + 90.0;
static constexpr double MAX_LONGITUDE_EPSILON = 1e-15 + 180.0;

bool ScannerMapCodeUtils::MetadataToMapCode(const Metadata &metadata)
{
    MEDIA_DEBUG_LOG("ScannerMapCodeUtils::MetadataToMapCode data_->GetFileId() %{private}d",
        metadata.GetFileId());
    NativeRdb::ValuesBucket mapValue;
    string whereMapClause = PhotoMapCodeColumn::MAPCODE_FILE_ID + " = ?";
    vector<string> whereMapArgs = { to_string(metadata.GetFileId()) };

    // 数据入库点
    double longitude = metadata.GetLongitude();
    double latitude = metadata.GetLatitude();
    const std::string mapTableName = PhotoMapCodeColumn::PHOTOS_MAP_CODE_TABLE;
    
    if (metadata.GetFileId() > 0 &&
        fabs(longitude) > DOUBLE_EPSILON && fabs(latitude) > DOUBLE_EPSILON &&
        fabs(longitude) < MAX_LONGITUDE_EPSILON && fabs(latitude) < MAX_LATITUDE_EPSILON) {
        PhotoMapData photoMapData(metadata.GetFileId(), latitude, longitude);
        int32_t ret = PhotoMapCodeOperation::GetPhotoMapCode(photoMapData, PhotoMapType::UPDATE_AND_INSERT);
        if (ret == E_OK) {
            return true;
        }
        return false;
    }
    return true;
}

bool ScannerMapCodeUtils::DeleteMapCodesByFileIds(const vector<string> &fileIds)
{
    MEDIA_INFO_LOG("ScannerMapCodeUtils::DeleteMapCodesByFileIds fileIds size %{public}zu", fileIds.size());
    if (fileIds.size() == 0) {
        return true;
    }

    int32_t ret = PhotoMapCodeOperation::RemovePhotosMapCodes(fileIds);
    return ret == E_OK;
}
} // namespace Media
} // namespace OHOS
