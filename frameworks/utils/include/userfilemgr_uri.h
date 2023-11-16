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
const std::string OPRN_CREATE_COMPONENT = "create_component";
const std::string OPRN_CLOSE = "close";
const std::string OPRN_DELETE = "delete";
const std::string OPRN_QUERY = "query";
const std::string OPRN_UPDATE = "update";
const std::string OPRN_TRASH = "trash";
const std::string OPRN_PENDING = "update_pending";
const std::string OPRN_SCAN = "scan";
const std::string OPRN_INDEX = "index";
const std::string OPRN_HIDE = "hide";
const std::string OPRN_QUERY_HIDDEN = "query_hidden";
const std::string OPRN_STORE_FORM_ID = "store_form_id";
const std::string OPRN_REMOVE_FORM_ID = "remove_form_id";
const std::string OPRN_ALBUM_ADD_PHOTOS = "add_photos";
const std::string OPRN_ALBUM_REMOVE_PHOTOS = "remove_photos";
const std::string OPRN_RECOVER_PHOTOS = "recover_photos";
const std::string OPRN_DELETE_PHOTOS = "delete_photos_permanently";   // Delete photos permanently from system
// Delete non-trashed photos directly from system for api9 MediaLibrary.delete compatibility
const std::string OPRN_COMPAT_DELETE_PHOTOS = "compat_delete_photos_permanently";
const std::string OPRN_DELETE_BY_TOOL = "delete_by_tool";
const std::string OPRN_SET_USER_COMMENT = "set_user_comment";
const std::string OPRN_COMMIT_EDIT = "operation_commit_edit";
const std::string OPRN_REVERT_EDIT = "operation_revert_edit";
const std::string OPRN_ORDER_ALBUM = "order_album";

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

// API9 compat photo operations constants
const std::string URI_CREATE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + MEDIA_PHOTOOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET;
const std::string URI_CLOSE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + MEDIA_PHOTOOPRN + "/" + MEDIA_FILEOPRN_CLOSEASSET;
const std::string URI_UPDATE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + MEDIA_PHOTOOPRN + "/" + OPRN_UPDATE;
const std::string URI_QUERY_PHOTO = MEDIALIBRARY_DATA_URI + "/" + MEDIA_PHOTOOPRN + "/" + OPRN_QUERY;
// API9 compat audio operations constants
const std::string URI_QUERY_AUDIO = MEDIALIBRARY_DATA_URI + "/" + MEDIA_AUDIOOPRN + "/" + OPRN_QUERY;
const std::string URI_CLOSE_AUDIO = MEDIALIBRARY_DATA_URI + "/" + MEDIA_AUDIOOPRN + "/" + MEDIA_FILEOPRN_CLOSEASSET;
const std::string URI_UPDATE_AUDIO = MEDIALIBRARY_DATA_URI + "/" + MEDIA_AUDIOOPRN + "/" + OPRN_UPDATE;
const std::string URI_CREATE_AUDIO = MEDIALIBRARY_DATA_URI + "/" + MEDIA_AUDIOOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET;
const std::string URI_CLOSE_FILE = MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CLOSEASSET;
const std::string URI_UPDATE_FILE = MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_MODIFYASSET;
const std::string URI_CREATE_FILE = MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET;

// Thumbnail operations constants
const std::string DISTRIBUTE_THU_OPRN_GENERATES = "thumbnail_distribute_generate_operation";
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
const std::string URI_QUERY_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PHOTO_ALBUM_OPRN + "/" + OPRN_QUERY;
const std::string URI_DELETE_PHOTOS = MEDIALIBRARY_DATA_URI + "/" + PHOTO_ALBUM_OPRN + "/" + OPRN_DELETE_PHOTOS;
const std::string URI_COMPAT_DELETE_PHOTOS = MEDIALIBRARY_DATA_URI + "/" + PHOTO_ALBUM_OPRN + "/" +
        OPRN_COMPAT_DELETE_PHOTOS;

// Photo map operations constants
const std::string PHOTO_MAP_OPRN = "photo_map_v10_operation";
const std::string URI_QUERY_PHOTO_MAP = MEDIALIBRARY_DATA_URI + "/" + PHOTO_MAP_OPRN + "/" + OPRN_QUERY;

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

// Scanner tool operation constants
const std::string SCANNER_OPRN = "scanner";
const std::string URI_SCANNER = MEDIALIBRARY_DATA_URI + "/" + SCANNER_OPRN + "/" + OPRN_SCAN;

// Mediatool delete operation constants
const std::string DELETE_TOOL_OPRN = "delete_tool";
const std::string URI_DELETE_TOOL = MEDIALIBRARY_DATA_URI + "/" + DELETE_TOOL_OPRN + "/" + OPRN_DELETE_BY_TOOL;

// UserFileManager operation constants
const std::string UFM_PHOTO = "userfilemgr_photo_operation";
const std::string UFM_AUDIO = "userfilemgr_audio_operation";
const std::string UFM_ALBUM = "userfilemgr_photo_album_operation";
const std::string UFM_MAP = "userfilemgr_photo_map_operation";

// UserFileManager photo operation constants
const std::string UFM_CREATE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + UFM_PHOTO + "/" + OPRN_CREATE;
const std::string UFM_CREATE_PHOTO_COMPONENT = MEDIALIBRARY_DATA_URI + "/" + UFM_PHOTO + "/" + OPRN_CREATE_COMPONENT;
const std::string UFM_CLOSE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + UFM_PHOTO + "/" + OPRN_CLOSE;
const std::string UFM_UPDATE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + UFM_PHOTO + "/" + OPRN_UPDATE;
const std::string UFM_QUERY_PHOTO = MEDIALIBRARY_DATA_URI + "/" + UFM_PHOTO + "/" + OPRN_QUERY;
const std::string UFM_SET_USER_COMMENT = MEDIALIBRARY_DATA_URI + "/" + UFM_PHOTO + "/" + OPRN_SET_USER_COMMENT;
const std::string UFM_GET_INDEX = MEDIALIBRARY_DATA_URI + "/" + UFM_PHOTO + "/" + OPRN_INDEX;
const std::string UFM_HIDE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + UFM_PHOTO + "/" + OPRN_HIDE;

// UserFileManager audio operation constants
const std::string UFM_CREATE_AUDIO = MEDIALIBRARY_DATA_URI + "/" + UFM_AUDIO + "/" + OPRN_CREATE;
const std::string UFM_CREATE_AUDIO_COMPONENT = MEDIALIBRARY_DATA_URI + "/" + UFM_AUDIO + "/" + OPRN_CREATE_COMPONENT;
const std::string UFM_CLOSE_AUDIO = MEDIALIBRARY_DATA_URI + "/" + UFM_AUDIO + "/" + OPRN_CLOSE;
const std::string UFM_QUERY_AUDIO = MEDIALIBRARY_DATA_URI + "/" + UFM_AUDIO + "/" + OPRN_QUERY;
const std::string UFM_UPDATE_AUDIO = MEDIALIBRARY_DATA_URI + "/" + UFM_AUDIO + "/" + OPRN_UPDATE;

// UserFileManager album operation constants
const std::string UFM_CREATE_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + UFM_ALBUM + "/" + OPRN_CREATE;
const std::string UFM_DELETE_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + UFM_ALBUM + "/" + OPRN_DELETE;
const std::string UFM_UPDATE_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + UFM_ALBUM + "/" + OPRN_UPDATE;
const std::string UFM_QUERY_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + UFM_ALBUM + "/" + OPRN_QUERY;
const std::string UFM_QUERY_HIDDEN_ALBUM = MEDIALIBRARY_DATA_URI + "/" + UFM_ALBUM + "/" + OPRN_QUERY_HIDDEN;
const std::string UFM_PHOTO_ALBUM_ADD_ASSET = MEDIALIBRARY_DATA_URI + "/" + UFM_MAP + "/" +
        OPRN_ALBUM_ADD_PHOTOS;
const std::string UFM_PHOTO_ALBUM_REMOVE_ASSET = MEDIALIBRARY_DATA_URI + "/" + UFM_MAP + "/" +
        OPRN_ALBUM_REMOVE_PHOTOS;
const std::string UFM_QUERY_PHOTO_MAP = MEDIALIBRARY_DATA_URI + "/" + UFM_MAP + "/" + OPRN_QUERY;
const std::string UFM_RECOVER_PHOTOS = MEDIALIBRARY_DATA_URI + "/" + UFM_ALBUM + "/" + OPRN_RECOVER_PHOTOS;
const std::string UFM_DELETE_PHOTOS = MEDIALIBRARY_DATA_URI + "/" + UFM_ALBUM + "/" + OPRN_DELETE_PHOTOS;

// PhotoAccessHelper operation constants
const std::string PAH_PHOTO = "phaccess_photo_operation";
const std::string PAH_ALBUM = "phaccess_album_operation";
const std::string PAH_MAP = "phaccess_map_operation";
const std::string PAH_ANA_ALBUM = "phaccess_ana_album_operation";
const std::string PAH_ANA_MAP = "phaccess_ana_map_operation";
const std::string PAH_ANA_OCR = "phaccess_ana_ocr_operation";
const std::string PAH_ANA_ATTS = "phaccess_ana_atts_operation";
const std::string PAH_FORM_MAP = "phaccess_store_form_operation";

// UserFileManager photo operation constants
const std::string PAH_CREATE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_CREATE;
const std::string PAH_CREATE_PHOTO_COMPONENT = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_CREATE_COMPONENT;
const std::string PAH_CLOSE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_CLOSE;
const std::string PAH_UPDATE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_UPDATE;
const std::string PAH_TRASH_PHOTO = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_TRASH;
const std::string PAH_QUERY_PHOTO = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_QUERY;
const std::string PAH_EDIT_USER_COMMENT_PHOTO = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_SET_USER_COMMENT;
const std::string PAH_HIDE_PHOTOS = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_HIDE;

// UserFileManager album operation constants
const std::string PAH_CREATE_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_ALBUM + "/" + OPRN_CREATE;
const std::string PAH_DELETE_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_ALBUM + "/" + OPRN_DELETE;
const std::string PAH_UPDATE_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_ALBUM + "/" + OPRN_UPDATE;
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

const std::string PAH_QUERY_ANA_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ALBUM + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_PHOTO_MAP = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_MAP + "/" + OPRN_QUERY;
const std::string PAH_INSERT_ANA_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ALBUM + "/" + OPRN_CREATE;
const std::string PAH_UPDATE_ANA_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ALBUM + "/" + OPRN_UPDATE;
const std::string PAH_INSERT_ANA_PHOTO_MAP = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_MAP + "/" + OPRN_CREATE;

const std::string PAH_QUERY_ANA_OCR = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_OCR + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_ATTS = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ATTS + "/" + OPRN_QUERY;
const std::string PAH_STORE_FORM_MAP = MEDIALIBRARY_DATA_URI + "/" + PAH_FORM_MAP + "/" + OPRN_STORE_FORM_ID;
const std::string PAH_REMOVE_FORM_MAP = MEDIALIBRARY_DATA_URI + "/" + PAH_FORM_MAP + "/" + OPRN_REMOVE_FORM_ID;

// mediatool operation constants
const std::string TOOL_PHOTO = "mediatool_photo_operation";
const std::string TOOL_AUDIO = "mediatool_audio_operation";

const std::string TOOL_CREATE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + TOOL_PHOTO + "/" + OPRN_CREATE;
const std::string TOOL_CREATE_AUDIO = MEDIALIBRARY_DATA_URI + "/" + TOOL_AUDIO + "/" + OPRN_CREATE;
const std::string TOOL_CLOSE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + TOOL_PHOTO + "/" + OPRN_CLOSE;
const std::string TOOL_CLOSE_AUDIO = MEDIALIBRARY_DATA_URI + "/" + TOOL_AUDIO + "/" + OPRN_CLOSE;
const std::string TOOL_QUERY_PHOTO = MEDIALIBRARY_DATA_URI + "/" + TOOL_PHOTO + "/" + OPRN_QUERY;
const std::string TOOL_QUERY_AUDIO = MEDIALIBRARY_DATA_URI + "/" + TOOL_AUDIO + "/" + OPRN_QUERY;
const std::string TOOL_UPDATE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + TOOL_PHOTO + "/" + OPRN_UPDATE;
const std::string TOOL_UPDATE_AUDIO = MEDIALIBRARY_DATA_URI + "/" + TOOL_AUDIO + "/" + OPRN_UPDATE;
const std::string TOOL_DELETE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + TOOL_PHOTO + "/" + OPRN_DELETE;
const std::string TOOL_DELETE_AUDIO = MEDIALIBRARY_DATA_URI + "/" + TOOL_AUDIO + "/" + OPRN_DELETE;
} // namespace Media
} // namespace OHOS

#endif // OHOS_FILEMANAGEMENT_USERFILEMGR_URI_H
