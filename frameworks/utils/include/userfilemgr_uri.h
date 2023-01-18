/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_FILEMANAGEMENT_USERFILEMGR_URI_H
#define OHOS_FILEMANAGEMENT_USERFILEMGR_URI_H

#include <string>

namespace OHOS {
namespace Media {
const std::string MEDIALIBRARY_DATA_URI = "datashare:///media";
const std::string MEDIA_OPERN_KEYWORD = "operation";
const std::string MEDIA_QUERYOPRN = "query_operation";
const std::string OPRN_CREATE = "create";
const std::string OPRN_DELETE = "delete";
const std::string OPRN_QUERY = "query";

// Asset operations constants
const std::string MEDIA_FILEOPRN = "file_operation";
const std::string MEDIA_PHOTOOPRN = "photo_operation";
const std::string MEDIA_AUDIOOPRN = "audio_operation";
const std::string MEDIA_DOCUMENTOPRN = "document_operation";
const std::string MEDIA_FILEOPRN_CREATEASSET = "create_asset";
const std::string MEDIA_FILEOPRN_MODIFYASSET = "modify_asset";
const std::string MEDIA_FILEOPRN_DELETEASSET = "delete_asset";
const std::string MEDIA_FILEOPRN_TRASHASSET = "trash_asset";
const std::string MEDIA_FILEOPRN_OPENASSET = "open_asset";
const std::string MEDIA_FILEOPRN_CLOSEASSET = "close_asset";
const std::string MEDIA_FILEOPRN_ISDIRECTORY = "isdirectory_asset";

// Thumbnail operations constants
const std::string THU_OPRN_GENERATES = "thumbnail_generate_operation";
const std::string THU_OPRN_AGING = "thumbnail_aging_operation";
const std::string DISTRIBUTE_THU_OPRN_GENERATES = "thumbnail_distribute_generate_operation";
const std::string DISTRIBUTE_THU_OPRN_AGING = "thumbnail_distribute_aging_operation";
const std::string DISTRIBUTE_THU_OPRN_CREATE = "thumbnail_distribute_create_operation";
const std::string BUNDLE_PERMISSION_INSERT = "bundle_permission_insert_operation";

// Album operations constants
const std::string MEDIA_ALBUMOPRN = "album_operation";
const std::string MEDIA_ALBUMOPRN_CREATEALBUM = "create_album";
const std::string MEDIA_ALBUMOPRN_MODIFYALBUM = "modify_album";
const std::string MEDIA_ALBUMOPRN_DELETEALBUM = "delete_album";
const std::string MEDIA_ALBUMOPRN_QUERYALBUM = "query_album";
const std::string MEDIA_FILEOPRN_GETALBUMCAPACITY = "get_album_capacity";

// Photo album operations constants
const std::string PHOTO_ALBUM_OPRN = "photo_album_v10_operation";
const std::string OPRN_ALBUM_ADD_ASSETS = "add_assets";
const std::string OPRN_ALBUM_REMOVE_ASSETS = "remove_assets";
const std::string URI_CREATE_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PHOTO_ALBUM_OPRN + "/" + OPRN_CREATE;
const std::string URI_DELETE_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PHOTO_ALBUM_OPRN + "/" + OPRN_DELETE;
const std::string URI_QUERY_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PHOTO_ALBUM_OPRN + "/" + OPRN_QUERY;
const std::string URI_PHOTO_ALBUM_ADD_ASSET = MEDIALIBRARY_DATA_URI + "/" + PHOTO_ALBUM_OPRN + "/" +
        OPRN_ALBUM_ADD_ASSETS;
const std::string URI_PHOTO_ALBUM_REMOVE_ASSET = MEDIALIBRARY_DATA_URI + "/" + PHOTO_ALBUM_OPRN + "/" +
        OPRN_ALBUM_REMOVE_ASSETS;

// SmartAlbum operations constants
const std::string MEDIA_SMARTALBUMOPRN = "albumsmart_operation";
const std::string MEDIA_SMARTALBUMMAPOPRN = "smartalbummap_operation";
const std::string MEDIA_SMARTALBUMOPRN_CREATEALBUM = "create_smartalbum";
const std::string MEDIA_SMARTALBUMOPRN_MODIFYALBUM = "modify_smartalbum";
const std::string MEDIA_SMARTALBUMOPRN_DELETEALBUM = "delete_smartalbum";
const std::string MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM = "add_smartalbum_map";
const std::string MEDIA_SMARTALBUMMAPOPRN_REMOVESMARTALBUM = "remove_smartalbum_map";
const std::string MEDIA_SMARTALBUMMAPOPRN_AGEINGSMARTALBUM = "ageing_smartalbum_map";

// Direcotry operations constants
const std::string MEDIA_DIROPRN = "dir_operation";
const std::string MEDIA_DIROPRN_DELETEDIR = "delete_dir";
const std::string MEDIA_DIROPRN_CHECKDIR_AND_EXTENSION = "check_dir_and_extension";
const std::string MEDIA_DIROPRN_FMS_CREATEDIR = "fms_create_dir";
const std::string MEDIA_DIROPRN_FMS_DELETEDIR = "fms_delete_dir";
const std::string MEDIA_DIROPRN_FMS_TRASHDIR = "fms_trash_dir";
const std::string MEDIA_QUERYOPRN_QUERYVOLUME = "query_media_volume";

// File operations constants
const std::string MEDIA_FILEOPRN_COPYASSET = "copy_asset";

// Distribution operations constants
const std::string MEDIA_BOARDCASTOPRN = "boardcast";
const std::string MEDIA_SCAN_OPERATION = "boardcast_scan";
const std::string MEDIA_DEVICE_QUERYALLDEVICE = "query_all_device";
const std::string MEDIA_DEVICE_QUERYACTIVEDEVICE = "query_active_device";
} // namespace Media
} // namespace OHOS

#endif // OHOS_FILEMANAGEMENT_USERFILEMGR_URI_H
