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

#ifndef MEDIALIBRARY_PTP_OPERATIONS_H
#define MEDIALIBRARY_PTP_OPERATIONS_H

#include "cloud_sync_manager.h"
#include "directory_ex.h"
#include "file_asset.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_command.h"
#include "moving_photo_file_utils.h"
#include "rdb_utils.h"

namespace OHOS {
namespace Media {

class MediaLibraryPtpOperations  {
public:
    EXPORT static int32_t DeletePtpPhoto(NativeRdb::RdbPredicates &predicates);
    EXPORT static int32_t DeletePtpAlbum(NativeRdb::RdbPredicates &predicates);
private:
    static std::shared_ptr<FileAsset> QueryPhotoInfo(NativeRdb::RdbPredicates &rdbPredicate);
    static int32_t UpdateBurstPhotoInfo(const std::string &burstKey, const bool isCover,
        NativeRdb::RdbPredicates &rdbPredicate);

    static std::shared_ptr<FileAsset> FetchOneFileAssetFromResultSet(
        const std::shared_ptr<NativeRdb::ResultSet> &resultSet, const std::vector<std::string> &columns);
    static std::shared_ptr<FileAsset> GetAssetFromResultSet(
        const std::shared_ptr<NativeRdb::ResultSet> &resultSet, const std::vector<std::string> &columns);
    static void PushMovingPhotoExternalPath(const std::string &path, const std::string &logTarget,
        std::vector<std::string> &attachment);
    static int64_t GetAssetSize(const std::string &extraPath);
    static void GetMovingPhotoExternalInfo(ExternalInfo &exInfo, std::vector<std::string> &attachment);
    static void GetEditPhotoExternalInfo(ExternalInfo &exInfo, std::vector<std::string> &attachment);
    static FileManagement::CloudSync::CleanFileInfo GetCleanFileInfo(std::shared_ptr<FileAsset> &fileAssetPtr);
    static bool BatchDeleteLocalAndCloud(const std::vector<FileManagement::CloudSync::CleanFileInfo> &fileInfos);
    static int32_t DeleteLocalAndCloudPhotos(std::vector<std::shared_ptr<FileAsset>> &subFileAsset);
    static bool isLastBurstPhoto(const std::string& burstKey);
};

} // namespace Media
} // namespace OHOS

#endif // MEDIALIBRARY_PTP_OPERATIONS_H