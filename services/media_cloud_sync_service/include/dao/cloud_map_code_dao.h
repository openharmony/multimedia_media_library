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

#ifndef CLOUD_MAP_CODE_UTILS_H
#define CLOUD_MAP_CODE_UTILS_H

#include "media_column.h"
#include "cloud_media_photos_dao.h"
#include "cloud_media_pull_data_dto.h"
#include "photo_map_code_operation.h"

#include "medialibrary_rdbstore.h"
#include "directory_ex.h"
#include "media_log.h"
#include "medialibrary_type_const.h"

#include "abs_rdb_predicates.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "cloud_media_file_utils.h"
#include "cloud_media_sync_utils.h"
#include "cloud_media_operation_code.h"
#include "medialibrary_unistore_manager.h"
#include "moving_photo_file_utils.h"
#include "result_set.h"
#include "result_set_utils.h"
#include "thumbnail_const.h"
#include "userfile_manager_types.h"
#include "result_set_reader.h"
#include "photos_po_writer.h"
#include "photos_po.h"
#include "photo_album_po_writer.h"
#include "cloud_sync_convert.h"
#include "medialibrary_rdb_transaction.h"
#include "medialibrary_rdb_utils.h"
#include "scanner_utils.h"
#include "cloud_media_dao_const.h"
#include "media_gallery_sync_notify.h"
#include "cloud_media_sync_const.h"
#include "cloud_media_dao_utils.h"

#include <cerrno>
#include <bitset>
#include <cmath>
#include <string>
#include <vector>
#include <sys/stat.h>

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

class CloudMapCodeDao {
public:
    EXPORT static int32_t InsertDatasToMapCode(std::vector<CloudSync::CloudMediaPullDataDto> &pullDatas);
    EXPORT static int32_t UpdateDataToMapCode(const CloudSync::CloudMediaPullDataDto &pullData);

    // 删除场景(MediaLibraryAssetOperations::DeleteFromDisk)
    EXPORT static int32_t DeleteMapCodesByPullDatas(std::vector<CloudSync::CloudMediaPullDataDto> &pullDatas);
    EXPORT static int32_t DeleteMapCodesByPullData(const CloudSync::CloudMediaPullDataDto &pullData);
private:
    EXPORT static int32_t GetPhotosPoByPullDatas(std::vector<CloudSync::CloudMediaPullDataDto> &pullDatas,
        std::vector<Media::ORM::PhotosPo> &photosPos, const std::vector<std::string> &getValues);
    EXPORT static int32_t GetPhotosPoByPullData(const CloudSync::CloudMediaPullDataDto &pullData,
        std::vector<Media::ORM::PhotosPo> &photosPos, const std::vector<std::string> &getValues);
};
} // namespace Media
} // namespace OHOS

#endif // MAP_CODE_UTILS_H
