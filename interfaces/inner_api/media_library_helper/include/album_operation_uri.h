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

#ifndef ALBUM_OPERATION_H_
#define ALBUM_OPERATION_H_
#include "base_data_uri.h"

namespace OHOS {
namespace Media {
const std::string OPRN_ALBUM_SET_NAME = "set_album_name";
// PhotoAccessHelper album operation constants
const std::string PAH_CREATE_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_ALBUM + "/" + OPRN_CREATE;
const std::string PAH_DELETE_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_ALBUM + "/" + OPRN_DELETE;
const std::string PAH_UPDATE_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_ALBUM + "/" + OPRN_UPDATE;
const std::string PAH_SET_PHOTO_ALBUM_NAME = MEDIALIBRARY_DATA_URI + "/" + PAH_ALBUM + "/" + OPRN_ALBUM_SET_NAME;
const std::string PAH_QUERY_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_ALBUM + "/" + OPRN_QUERY;
const std::string PAH_QUERY_HIDDEN_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_ALBUM + "/" + OPRN_QUERY_HIDDEN;
const std::string PAH_PHOTO_ALBUM_ADD_ASSET = MEDIALIBRARY_DATA_URI + "/" + PAH_MAP + "/" +
        OPRN_ALBUM_ADD_PHOTOS;
const std::string PAH_PHOTO_ALBUM_REMOVE_ASSET = MEDIALIBRARY_DATA_URI + "/" + PAH_MAP + "/" +
        OPRN_ALBUM_REMOVE_PHOTOS;
const std::string PAH_QUERY_PHOTO_MAP = MEDIALIBRARY_DATA_URI + "/" + PAH_MAP + "/" + OPRN_QUERY;
const std::string PAH_RECOVER_PHOTOS = MEDIALIBRARY_DATA_URI + "/" + PAH_ALBUM + "/" + OPRN_RECOVER_PHOTOS;
const std::string PAH_DELETE_PHOTOS = MEDIALIBRARY_DATA_URI + "/" + PAH_ALBUM + "/" + OPRN_DELETE_PHOTOS;
const std::string PAH_ORDER_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_ALBUM + "/" + OPRN_ORDER_ALBUM;
const std::string PAH_COMMIT_EDIT_PHOTOS = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_COMMIT_EDIT;
const std::string PAH_REVERT_EDIT_PHOTOS = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_REVERT_EDIT;
const std::string PAH_PORTRAIT_DISPLAY_LEVLE = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ALBUM + "/" +
    OPRN_PORTRAIT_DISPLAY_LEVEL;
const std::string PAH_PORTRAIT_IS_ME = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ALBUM + "/" + OPRN_PORTRAIT_IS_ME;
const std::string PAH_PORTRAIT_ANAALBUM_ALBUM_NAME = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ALBUM + "/" +
    OPRN_PORTRAIT_ALBUM_NAME;
const std::string PAH_PORTRAIT_MERGE_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ALBUM + "/" +
    OPRN_PORTRAIT_MERGE_ALBUM;
const std::string PAH_HIGHLIGHT_ALBUM_NAME = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ALBUM + "/" +
    OPRN_HIGHLIGHT_ALBUM_NAME;
const std::string PAH_HIGHLIGHT_COVER_URI = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ALBUM + "/" +
    OPRN_HIGHLIGHT_COVER_URI;
const std::string PAH_HIGHLIGHT_SUBTITLE = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ALBUM + "/" +
    OPRN_HIGHLIGHT_SUBTITLE;
const std::string PAH_DISMISS_ASSET = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_MAP + "/" +
    OPRN_DISMISS_ASSET;
const std::string PAH_PORTRAIT_ANAALBUM_COVER_URI = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ALBUM + "/" +
    OPRN_PORTRAIT_COVER_URI;
const std::string PAH_GROUP_ANAALBUM_DISMISS = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ALBUM + "/" +
    OPRN_GROUP_DISMISS;
const std::string PAH_GROUP_ANAALBUM_ALBUM_NAME = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ALBUM + "/" +
    OPRN_GROUP_ALBUM_NAME;
const std::string PAH_GROUP_ANAALBUM_COVER_URI = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ALBUM + "/" +
    OPRN_GROUP_COVER_URI;
} // namespace Media
} // namespace OHOS

#endif // ALBUM_OPERATION_H_