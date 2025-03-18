/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef NOTIFYCHANGE_FUZZER_H
#define NOTIFYCHANGE_FUZZER_H

#define FUZZ_PROJECT_NAME "medialibraryextension_fuzzer"

#include "userfilemgr_uri.h"
#include "album_operation_uri.h"
#include "data_secondary_directory_uri.h"
#include "cloud_enhancement_uri.h"
#include "mediatool_uri.h"

#include <string>
#include <vector>

namespace OHOS {
namespace Media {
const std::vector<std::string> EXTENSION_FUZZER_URI_LISTS = {
    // API9 compat photo operations constants
    URI_CREATE_PHOTO,
    URI_CLOSE_PHOTO,
    URI_UPDATE_PHOTO,
    URI_QUERY_PHOTO,

    // API9 compat audio operations constants
    URI_QUERY_AUDIO,
    URI_CLOSE_AUDIO,
    URI_UPDATE_AUDIO,
    URI_CREATE_AUDIO,
    URI_CLOSE_FILE,
    URI_UPDATE_FILE,
    URI_CREATE_FILE,

    // Photo album operations constants
    URI_QUERY_PHOTO_ALBUM,
    URI_DELETE_PHOTOS,
    URI_COMPAT_DELETE_PHOTOS,

    // Photo map operations constants
    URI_QUERY_PHOTO_MAP,

    // Scanner tool operation constants
    URI_SCANNER,

    // Mediatool delete operation constants
    URI_DELETE_TOOL,

    // UserFileManager photo operation constants
    UFM_CREATE_PHOTO,
    UFM_CREATE_PHOTO_COMPONENT,
    UFM_CLOSE_PHOTO,
    UFM_UPDATE_PHOTO,
    UFM_QUERY_PHOTO,
    UFM_SET_USER_COMMENT,
    UFM_GET_INDEX,
    UFM_HIDE_PHOTO,

    // UserFileManager audio operation constants
    UFM_CREATE_AUDIO,
    UFM_CREATE_AUDIO_COMPONENT,
    UFM_CLOSE_AUDIO,
    UFM_QUERY_AUDIO,
    UFM_UPDATE_AUDIO,
    URI_DELETE_AUDIO,

    // UserFileManager album operation constants
    UFM_CREATE_PHOTO_ALBUM,
    UFM_DELETE_PHOTO_ALBUM,
    UFM_UPDATE_PHOTO_ALBUM,
    UFM_QUERY_PHOTO_ALBUM,
    UFM_QUERY_HIDDEN_ALBUM,
    UFM_PHOTO_ALBUM_ADD_ASSET,
    UFM_PHOTO_ALBUM_REMOVE_ASSET,
    UFM_QUERY_PHOTO_MAP,
    UFM_RECOVER_PHOTOS,
    UFM_DELETE_PHOTOS,

    // PhotoAccessHelper photo operation constants
    PAH_CREATE_PHOTO,
    PAH_CREATE_PHOTO_COMPONENT,
    PAH_CLOSE_PHOTO,
    PAH_UPDATE_PHOTO,
    PAH_UPDATE_PHOTO_COMPONENT,
    PAH_TRASH_PHOTO,
    PAH_QUERY_PHOTO,
    PAH_EDIT_USER_COMMENT_PHOTO,
    PAH_HIDE_PHOTOS,
    PAH_SUBMIT_CACHE,
    PAH_ADD_FILTERS,
    PAH_BATCH_UPDATE_FAVORITE,
    PAH_BATCH_UPDATE_USER_COMMENT,
    PAH_BATCH_UPDATE_OWNER_ALBUM_ID,
    PAH_GET_ANALYSIS_INDEX,
    PAH_DISCARD_CAMERA_PHOTO,
    PAH_SAVE_CAMERA_PHOTO,
    PAH_SCAN_WITHOUT_ALBUM_UPDATE,
    PATH_SAVE_PICTURE,

    // MultiStages capture related operation uri
    PAH_SET_PHOTO_QUALITY,
    PAH_PROCESS_IMAGE,
    PAH_ADD_IMAGE,
    PAH_SET_LOCATION,
    PAH_CANCEL_PROCESS_IMAGE,
    PAH_REMOVE_MSC_TASK,

    // Generate thumbnails in batches operation uri
    PAH_START_GENERATE_THUMBNAILS,
    PAH_STOP_GENERATE_THUMBNAILS,
    PAH_ADD_LOWQUALITY_IMAGE,

    // PhotoAccessHelper album operation constants
    PAH_CREATE_PHOTO_ALBUM,
    PAH_DELETE_PHOTO_ALBUM,
    PAH_UPDATE_PHOTO_ALBUM,
    PAH_SET_PHOTO_ALBUM_NAME,
    PAH_QUERY_PHOTO_ALBUM,
    PAH_QUERY_HIDDEN_ALBUM,
    PAH_PHOTO_ALBUM_ADD_ASSET,
    PAH_PHOTO_ALBUM_REMOVE_ASSET,
    PAH_QUERY_PHOTO_MAP,
    PAH_RECOVER_PHOTOS,
    PAH_DELETE_PHOTOS,
    PAH_ORDER_ALBUM,
    PAH_COMMIT_EDIT_PHOTOS,
    PAH_REVERT_EDIT_PHOTOS,
    PAH_PORTRAIT_DISPLAY_LEVLE,
    PAH_PORTRAIT_IS_ME,
    PAH_PORTRAIT_ANAALBUM_ALBUM_NAME,
    PAH_PORTRAIT_MERGE_ALBUM,
    PAH_DISMISS_ASSET,
    PAH_PORTRAIT_ANAALBUM_COVER_URI,
    PAH_GROUP_ANAALBUM_DISMISS,
    PAH_GROUP_ANAALBUM_ALBUM_NAME,
    PAH_GROUP_ANAALBUM_COVER_URI,
    PAH_HIGHLIGHT_COVER_URI,
    PAH_HIGHLIGHT_ALBUM_NAME,

    PAH_QUERY_ANA_PHOTO_ALBUM,
    PAH_QUERY_ANA_PHOTO_MAP,
    PAH_INSERT_ANA_PHOTO_ALBUM,
    PAH_UPDATE_ANA_PHOTO_ALBUM,
    PAH_INSERT_ANA_PHOTO_MAP,

    PAH_QUERY_ANA_OCR,
    PAH_QUERY_ANA_ATTS,
    PAH_QUERY_ANA_LABEL,
    PAH_QUERY_ANA_VIDEO_LABEL,
    PAH_QUERY_ANA_FACE,
    PAH_QUERY_ANA_FACE_TAG,
    PAH_QUERY_ANA_OBJECT,
    PAH_QUERY_ANA_RECOMMENDATION,
    PAH_QUERY_ANA_SEGMENTATION,
    PAH_QUERY_ANA_COMPOSITION,
    PAH_QUERY_ANA_HEAD,
    PAH_QUERY_ANA_POSE,
    PAH_STORE_FORM_MAP,
    PAH_REMOVE_FORM_MAP,
    PAH_QUERY_ANA_SAL,
    PAH_QUERY_ANA_ADDRESS,
    PAH_QUERY_GEO_PHOTOS,
    PAH_QUERY_HIGHLIGHT_COVER,
    PAH_QUERY_HIGHLIGHT_PLAY,
    PAH_QUERY_ANA_TOTAL,
    PAH_QUERY_MULTI_CROP,
    PAH_UPDATE_ANA_FACE,

    // PhotoAccessHelper moving photo
    PAH_MOVING_PHOTO_SCAN,

    // PhotoAccessHelper cloud enhancement
    PAH_CLOUD_ENHANCEMENT_ADD,
    PAH_CLOUD_ENHANCEMENT_PRIORITIZE,
    PAH_CLOUD_ENHANCEMENT_CANCEL,
    PAH_CLOUD_ENHANCEMENT_CANCEL_ALL,
    PAH_CLOUD_ENHANCEMENT_SYNC,
    PAH_CLOUD_ENHANCEMENT_QUERY,
    PAH_CLOUD_ENHANCEMENT_GET_PAIR,

    // mediatool operation constants
    TOOL_CREATE_PHOTO,
    TOOL_CREATE_AUDIO,
    TOOL_CLOSE_PHOTO,
    TOOL_CLOSE_AUDIO,
    TOOL_QUERY_PHOTO,
    TOOL_QUERY_AUDIO,
    TOOL_LIST_PHOTO,
    TOOL_LIST_AUDIO,
    TOOL_UPDATE_PHOTO,
    TOOL_UPDATE_AUDIO,
    TOOL_DELETE_PHOTO,
    TOOL_DELETE_AUDIO,

    // Miscellaneous operation constants
    LOG_MOVING_PHOTO,
    PAH_FINISH_REQUEST_PICTURE,

    MEDIALIBRARY_DIRECTORY_URI,
    MEDIALIBRARY_BUNDLEPERM_URI,

    MEDIALIBRARY_CHECK_URIPERM_URI,
    MEDIALIBRARY_GRANT_URIPERM_URI,

    MEDIALIBRARY_AUDIO_URI,
    MEDIALIBRARY_VIDEO_URI,
    MEDIALIBRARY_IMAGE_URI,
    MEDIALIBRARY_FILE_URI,
    MEDIALIBRARY_ALBUM_URI,
    MEDIALIBRARY_SMARTALBUM_CHANGE_URI,
    MEDIALIBRARY_DEVICE_URI,
    MEDIALIBRARY_SMART_URI,
    MEDIALIBRARY_REMOTEFILE_URI,
};
} // namespace Media
} // namespace OHOS
#endif