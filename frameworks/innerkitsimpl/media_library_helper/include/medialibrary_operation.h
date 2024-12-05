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

#ifndef FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_MEDIA_OPERATION_H
#define FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_MEDIA_OPERATION_H

#include <map>
#include <string>

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
    TOOL_ALBUM,
    VISION_START,
    VISION_OCR = VISION_START,
    VISION_LABEL,
    VISION_VIDEO_LABEL,
    VISION_AESTHETICS,
    VISION_OBJECT,
    VISION_RECOMMENDATION,
    VISION_SEGMENTATION,
    VISION_COMPOSITION,
    VISION_TOTAL,
    VISION_IMAGE_FACE,
    VISION_VIDEO_FACE,
    VISION_FACE_TAG,
    VISION_SALIENCY,
    VISION_HEAD,
    VISION_POSE,
    VISION_END = VISION_POSE,
    GEO_DICTIONARY,
    GEO_KNOWLEDGE,
    GEO_PHOTO,
    ANALYSIS_PHOTO_ALBUM,
    ANALYSIS_PHOTO_MAP,
    PAH_FORM_MAP,
    SEARCH_TOTAL,  // search
    INDEX_CONSTRUCTION_STATUS,  //Search Index Build Status
    STORY_ALBUM,
    STORY_COVER,
    STORY_PLAY,
    USER_PHOTOGRAPHY,
    PAH_MULTISTAGES_CAPTURE,
    HIGHLIGHT_COVER,
    HIGHLIGHT_URI,
    PAH_MOVING_PHOTO,
    MISCELLANEOUS,
    PAH_BATCH_THUMBNAIL_OPERATE,
    APP_URI_PERMISSION_INNER,
    MEDIA_APP_URI_PERMISSION,
    REQUEST_PICTURE,
    PHOTO_REQUEST_PICTURE_BUFFER,
    PAH_CLOUD_ENHANCEMENT_OPERATE,
    PAH_VIDEO,
    ANALYSIS_ASSET_SD_MAP,
    ANALYSIS_ALBUM_ASSET_MAP,
    TAB_OLD_PHOTO,
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
    ALBUM_SET_NAME,
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
    DISMISS,
    GROUP_ALBUM_NAME,
    GROUP_COVER_URI,
    SUBMIT_CACHE,
    BATCH_UPDATE_FAV,
    BATCH_UPDATE_USER_COMMENT,
    BATCH_UPDATE_OWNER_ALBUM_ID,
    SET_PHOTO_QUALITY,
    ADD_IMAGE,
    PROCESS_IMAGE,
    SET_LOCATION,
    ANALYSIS_INDEX,
    CANCEL_PROCESS_IMAGE,
    LOG_MOVING_PHOTO,
    ADD_FILTERS,
    DISCARD_CAMERA_PHOTO,
    SAVE_CAMERA_PHOTO,
    REMOVE_MSC_TASK,
    START_GENERATE_THUMBNAILS,
    STOP_GENERATE_THUMBNAILS,
    GENERATE_THUMBNAILS_RESTORE,
    TOOL_QUERY_BY_DISPLAY_NAME,
    ADD_LOWQUALITY_IMAGE,
    FINISH_REQUEST_PICTURE,
    SCAN_WITHOUT_ALBUM_UPDATE,
    ENHANCEMENT_ADD,
    ENHANCEMENT_PRIORITIZE,
    ENHANCEMENT_QUERY,
    ENHANCEMENT_CANCEL,
    ENHANCEMENT_CANCEL_ALL,
    ENHANCEMENT_SYNC,
    ENHANCEMENT_GET_PAIR,
    SET_VIDEO_ENHANCEMENT_ATTR,
    LOG_MEDIALIBRARY_API,
    SAVE_PICTURE,
    CLONE_ASSET,
    DEGENERATE_MOVING_PHOTO,
    ALL_DUPLICATE_ASSETS,
    CAN_DEL_DUPLICATE_ASSETS,
};

#define OPRN_OBJ_MAP MediaOperation::GetOprnObjMap()
#define TABLE_NAME_MAP MediaOperation::GetTableNameMap()
#define OPRN_TYPE_MAP MediaOperation::GetOprnTypeMap()
#define OPRN_MAP MediaOperation::GetOprnMap()

namespace MediaOperation {
const std::map<std::string, OperationObject>& GetOprnObjMap();
const std::map<OperationObject, std::map<OperationType, std::string>>& GetTableNameMap();
const std::map<std::string, OperationType>& GetOprnTypeMap();
const std::map<std::string, OperationObject>& GetOprnMap();
} // namespace MediaOperation

} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_MEDIA_OPERATION_H
