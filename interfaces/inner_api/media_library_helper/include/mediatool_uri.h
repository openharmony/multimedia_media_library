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

#ifndef MEDIATOOL_URI_H_
#define MEDIATOOL_URI_H_
#include "base_data_uri.h"
namespace OHOS {
namespace Media {
const std::string TOOL_PHOTO = "mediatool_photo_operation";
const std::string TOOL_AUDIO = "mediatool_audio_operation";
const std::string TOOL_ALBUM = "mediatool_album_operation";
const std::string OPRN_TOOL_QUERY_BY_DISPLAY_NAME = "tool_query_by_display_name";

const std::string TOOL_CREATE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + TOOL_PHOTO + "/" + OPRN_CREATE;
const std::string TOOL_CREATE_AUDIO = MEDIALIBRARY_DATA_URI + "/" + TOOL_AUDIO + "/" + OPRN_CREATE;
const std::string TOOL_CLOSE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + TOOL_PHOTO + "/" + OPRN_CLOSE;
const std::string TOOL_CLOSE_AUDIO = MEDIALIBRARY_DATA_URI + "/" + TOOL_AUDIO + "/" + OPRN_CLOSE;
const std::string TOOL_QUERY_PHOTO = MEDIALIBRARY_DATA_URI + "/" + TOOL_PHOTO + "/" + OPRN_TOOL_QUERY_BY_DISPLAY_NAME;
const std::string TOOL_QUERY_AUDIO = MEDIALIBRARY_DATA_URI + "/" + TOOL_AUDIO + "/" + OPRN_TOOL_QUERY_BY_DISPLAY_NAME;
const std::string TOOL_LIST_PHOTO = MEDIALIBRARY_DATA_URI + "/" + TOOL_PHOTO + "/" + OPRN_QUERY;
const std::string TOOL_LIST_AUDIO = MEDIALIBRARY_DATA_URI + "/" + TOOL_AUDIO + "/" + OPRN_QUERY;
const std::string TOOL_UPDATE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + TOOL_PHOTO + "/" + OPRN_UPDATE;
const std::string TOOL_UPDATE_AUDIO = MEDIALIBRARY_DATA_URI + "/" + TOOL_AUDIO + "/" + OPRN_UPDATE;
const std::string TOOL_DELETE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + TOOL_ALBUM + "/" + OPRN_DELETE_PHOTOS;
const std::string TOOL_DELETE_AUDIO = MEDIALIBRARY_DATA_URI + "/" + TOOL_AUDIO + "/" + OPRN_DELETE;

const std::string IS_TOOL_OPEN = "is_mediatool_open_operation";
const std::string TOOL_OPEN_TRUE = "1";
} // namespace Media
} // namespace OHOS

#endif // MEDIATOOL_URI_H_