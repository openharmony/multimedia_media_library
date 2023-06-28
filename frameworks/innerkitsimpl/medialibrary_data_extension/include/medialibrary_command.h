/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_COMMAND_PARSE_H
#define OHOS_MEDIALIBRARY_COMMAND_PARSE_H

#include <string>
#include <unordered_map>
#include <vector>

#include "abs_rdb_predicates.h"
#include "datashare_predicates.h"
#include "dir_asset.h"
#include "medialibrary_db_const.h"
#include "uri.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
enum class OperationObject : uint32_t {
    UNKNOWN_OBJECT = 0,
    FILESYSTEM_ASSET,
    FILESYSTEM_PHOTO,
    FILESYSTEM_AUDIO,
    FILESYSTEM_DIR,
    FILESYSTEM_ALBUM,
    SMART_ALBUM,
    SMART_ALBUM_MAP,
    THUMBNAIL,
    SMART_ALBUM_ASSETS,
    ASSETMAP,
    ALL_DEVICE,
    ACTIVE_DEVICE,
    MEDIA_VOLUME,
    BUNDLE_PERMISSION,
    PHOTO_ALBUM,
    PHOTO_MAP,
    UFM_PHOTO,
    UFM_AUDIO,
    UFM_ALBUM,
    UFM_MAP,
};

enum class OperationType : uint32_t {
    UNKNOWN_TYPE = 0,
    OPEN,
    CLOSE,
    CREATE,
    DELETE,
    UPDATE,
    QUERY,
    GETCAPACITY,
    SCAN,
    TRASH,
    GENERATE,
    AGING,
    DISTRIBUTE_AGING,
    DISTRIBUTE_CREATE,
    COPY,
    INSERT_PERMISSION,
    ALBUM_ADD_PHOTOS,
    ALBUM_REMOVE_PHOTOS,
    ALBUM_RECOVER_ASSETS,
    ALBUM_DELETE_ASSETS,                // Delete assets permanently from system
};

class MediaLibraryCommand {
public:
    explicit MediaLibraryCommand(const Uri &uri);
    MediaLibraryCommand(const Uri &uri, const NativeRdb::ValuesBucket &value);
    MediaLibraryCommand(const Uri &uri, const OperationType &oprnType);
    MediaLibraryCommand(const OperationObject &oprnObject, const OperationType &oprnType,
        MediaLibraryApi api = MediaLibraryApi::API_OLD);
    MediaLibraryCommand(const OperationObject &oprnObject, const OperationType &oprnType,
        const NativeRdb::ValuesBucket &value, MediaLibraryApi api = MediaLibraryApi::API_OLD);
    MediaLibraryCommand(const OperationObject &oprnObject, const OperationType &oprnType,
        const std::string &networkId, MediaLibraryApi api = MediaLibraryApi::API_OLD);
    MediaLibraryCommand() = delete;
    ~MediaLibraryCommand();
    MediaLibraryCommand(const MediaLibraryCommand &) = delete;
    MediaLibraryCommand &operator=(const MediaLibraryCommand &) = delete;
    MediaLibraryCommand(MediaLibraryCommand &&) = delete;
    MediaLibraryCommand &operator=(MediaLibraryCommand &&) = delete;

    OperationObject GetOprnObject() const;
    OperationType GetOprnType() const;
    const std::string &GetTableName();
    NativeRdb::ValuesBucket &GetValueBucket();
    NativeRdb::AbsRdbPredicates *GetAbsRdbPredicates();
    const std::string &GetOprnFileId();
    const std::string &GetOprnDevice();
    const Uri &GetUri() const;
    const std::string &GetBundleName();
    const std::string &GetDeviceName();
    std::string GetUriStringWithoutSegment() const;
    MediaLibraryApi GetApi();
    std::string GetQuerySetParam(const std::string &key);
    void SetDataSharePred(const DataShare::DataSharePredicates &pred);
    const DataShare::DataSharePredicates &GetDataSharePred() const;

    void SetOprnObject(OperationObject object);
    void SetOprnAssetId(const std::string &oprnId);
    void SetValueBucket(const NativeRdb::ValuesBucket &value);
    void SetTableName(const std::string &tableName);
    void SetBundleName(const std::string &bundleName);
    void SetDeviceName(const std::string &deviceName);

private:
    void SetOprnDevice(const std::string &networkId);
    void ParseOprnObjectFromUri();
    void ParseOprnTypeFromUri();
    void ParseTableName();
    void InitAbsRdbPredicates();
    void ParseFileId();
    void ParseQuerySetMapFromUri();
    void SetApiFromQuerySetMap();
    void ParseOprnObjectFromFileUri();

    Uri uri_{""};
    NativeRdb::ValuesBucket insertValue_;
    std::unique_ptr<NativeRdb::AbsRdbPredicates> absRdbPredicates_;
    std::unique_ptr<const DataShare::DataSharePredicates> datasharePred_;
    OperationObject oprnObject_{OperationObject::UNKNOWN_OBJECT};
    OperationType oprnType_{OperationType::UNKNOWN_TYPE};
    std::string oprnFileId_;
    std::string oprnDevice_;
    std::string tableName_;
    std::string bundleName_;
    std::string deviceName_;
    std::unordered_map<std::string, std::string> querySetMap_;
    MediaLibraryApi api_;
};
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_COMMAND_PARSE_H
