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
#define EXPORT __attribute__ ((visibility ("default")))
enum class EXPORT OperationObject : uint32_t {
    UNKNOWN_OBJECT = 0,
    FILESYSTEM_ASSET,
    FILESYSTEM_PHOTO,
    FILESYSTEM_AUDIO,
    FILESYSTEM_DIR,
    FILESYSTEM_ALBUM,
    SMART_ALBUM,
    SMART_ALBUM_MAP,
    THUMBNAIL,
    THUMBNAIL_ASTC,
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
    PAH_PHOTO,
    PAH_ALBUM,
    PAH_MAP,
    TOOL_PHOTO,
    TOOL_AUDIO,
    VISION_START,
    VISION_OCR = VISION_START,
    VISION_LABEL,
    VISION_AESTHETICS,
    VISION_OBJECT,
    VISION_RECOMMENDATION,
    VISION_SEGMENTATION,
    VISION_COMPOSITION,
    VISION_TOTAL,
    VISION_IMAGE_FACE,
    VISION_FACE_TAG,
    VISION_SALIENCY,
    VISION_END = VISION_SALIENCY,
    GEO_DICTIONARY,
    GEO_KNOWLEDGE,
    GEO_PHOTO,
    ANALYSIS_PHOTO_ALBUM,
    ANALYSIS_PHOTO_MAP,
    PAH_FORM_MAP,
    SEARCH_TOTAL,  // search
    STORY_ALBUM,
    STORY_COVER,
    STORY_PLAY,
    USER_PHOTOGRAPHY,
    PAH_MULTISTAGES_CAPTURE,
};

enum class EXPORT OperationType : uint32_t {
    UNKNOWN_TYPE = 0,
    OPEN,
    CLOSE,
    CREATE,
    DELETE,
    DELETE_TOOL,
    UPDATE,
    QUERY,
    GETCAPACITY,
    SCAN,
    TRASH,
    GENERATE,
    AGING,
    DISTRIBUTE_AGING,
    COPY,
    INSERT_PERMISSION,
    ALBUM_ADD_PHOTOS,
    ALBUM_REMOVE_PHOTOS,
    ALBUM_RECOVER_ASSETS,
    ALBUM_DELETE_ASSETS,                // Delete assets permanently from system
    TRASH_PHOTO,
    UPDATE_PENDING,
    SET_USER_COMMENT,
    INDEX,
    COMPAT_ALBUM_DELETE_ASSETS,
    COMMIT_EDIT,
    REVERT_EDIT,
    HIDE,
    QUERY_HIDDEN,
    ALBUM_ORDER,
    OPRN_STORE_FORM_ID,
    OPRN_REMOVE_FORM_ID,
    PORTRAIT_DISPLAY_LEVEL,
    PORTRAIT_IS_ME,
    PORTRAIT_ALBUM_NAME,
    PORTRAIT_MERGE_ALBUM,
    DISMISS_ASSET,
    PORTRAIT_COVER_URI,
    SUBMIT_CACHE,
    BATCH_UPDATE_FAV,
    BATCH_UPDATE_USER_COMMENT,
    SET_PHOTO_QUALITY,
    ADD_IMAGE,
    PROCESS_IMAGE,
    SET_LOCATION,
    ANALYSIS_INDEX,
};

class MediaLibraryCommand {
public:
    EXPORT explicit MediaLibraryCommand(const Uri &uri);
    EXPORT MediaLibraryCommand(const Uri &uri, const NativeRdb::ValuesBucket &value);
    EXPORT MediaLibraryCommand(const Uri &uri, const OperationType &oprnType);
    EXPORT MediaLibraryCommand(const OperationObject &oprnObject, const OperationType &oprnType,
        MediaLibraryApi api = MediaLibraryApi::API_OLD);
    EXPORT MediaLibraryCommand(const OperationObject &oprnObject, const OperationType &oprnType,
        const NativeRdb::ValuesBucket &value, MediaLibraryApi api = MediaLibraryApi::API_OLD);
    EXPORT MediaLibraryCommand(const OperationObject &oprnObject, const OperationType &oprnType,
        const std::string &networkId, MediaLibraryApi api = MediaLibraryApi::API_OLD);
    EXPORT MediaLibraryCommand() = delete;
    EXPORT ~MediaLibraryCommand();
    EXPORT MediaLibraryCommand(const MediaLibraryCommand &) = delete;
    EXPORT MediaLibraryCommand &operator=(const MediaLibraryCommand &) = delete;
    EXPORT MediaLibraryCommand(MediaLibraryCommand &&) = delete;
    EXPORT MediaLibraryCommand &operator=(MediaLibraryCommand &&) = delete;

    OperationObject GetOprnObject() const;
    OperationType GetOprnType() const;
    const std::string &GetTableName();
    NativeRdb::ValuesBucket &GetValueBucket();
    EXPORT NativeRdb::AbsRdbPredicates *GetAbsRdbPredicates();
    const std::string &GetOprnFileId();
    const std::string &GetOprnDevice();
    const Uri &GetUri() const;
    const std::string &GetBundleName();
    const std::string &GetDeviceName();
    EXPORT std::string GetUriStringWithoutSegment() const;
    MediaLibraryApi GetApi();
    std::string GetQuerySetParam(const std::string &key);
    EXPORT void SetDataSharePred(const DataShare::DataSharePredicates &pred);
    const DataShare::DataSharePredicates &GetDataSharePred() const;
    const std::string &GetResult();

    EXPORT void SetOprnObject(OperationObject object);
    EXPORT void SetOprnAssetId(const std::string &oprnId);
    EXPORT void SetValueBucket(const NativeRdb::ValuesBucket &value);
    EXPORT void SetTableName(const std::string &tableName);
    void SetBundleName(const std::string &bundleName);
    void SetDeviceName(const std::string &deviceName);
    void SetResult(const std::string &result);

private:
    void ParseOprnObjectFromUri();
    void ParseOprnTypeFromUri();
    void ParseTableName();
    void InitAbsRdbPredicates();
    void ParseFileId();
    void ParseQuerySetMapFromUri();
    void SetApiFromQuerySetMap();
    void ParseOprnObjectFromFileUri();

    Uri uri_ {""};
    NativeRdb::ValuesBucket insertValue_;
    std::unique_ptr<NativeRdb::AbsRdbPredicates> absRdbPredicates_;
    std::unique_ptr<const DataShare::DataSharePredicates> datasharePred_;
    OperationObject oprnObject_ {OperationObject::UNKNOWN_OBJECT};
    OperationType oprnType_ {OperationType::UNKNOWN_TYPE};
    std::string oprnFileId_;
    std::string oprnDevice_;
    std::string tableName_;
    std::string bundleName_;
    std::string deviceName_;
    std::unordered_map<std::string, std::string> querySetMap_;
    std::string result_;
    MediaLibraryApi api_;
};
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_COMMAND_PARSE_H
