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
#include "base_data_uri.h"

namespace OHOS {
namespace Media {
const std::string MEDIA_OPERN_KEYWORD = "operation";
const std::string MEDIA_TRIGGER_MODE_KEYWORD = "trigger_mode";
const std::string MEDIA_MOVING_PHOTO_OPRN_KEYWORD = "moving_photo_operation";
const std::string OPRN_SYS_CREATE = "sys_create";
const std::string OPRN_CUSTOM_RESTORE = "custom_restore";
const std::string OPRN_CUSTOM_RESTORE_CANCEL = "custom_restore_cancel";
const std::string OPRN_CREATE_COMPONENT = "create_component";
const std::string OPRN_QUERY_ORDER = "query_order";
const std::string OPRN_UPDATE_ORDER = "update_order";
const std::string OPRN_SAVE_CAMERA_PHOTO_COMPONENT = "save_camera_photo_component";
const std::string OPRN_TRASH = "trash";
const std::string OPRN_SYS_TRASH = "sys_trash";
const std::string OPRN_PENDING = "update_pending";
const std::string OPRN_SCAN = "scan";
const std::string OPRN_INDEX = "index";
const std::string OPRN_ANALYSIS_INDEX = "analysis_index";
const std::string OPRN_HIDE = "hide";
const std::string OPRN_BATCH_UPDATE_FAV = "batch_update_favorite";
const std::string OPRN_BATCH_UPDATE_USER_COMMENT = "batch_update_user_comment";
const std::string OPRN_BATCH_UPDATE_OWNER_ALBUM_ID = "batch_update_owner_album_id";
const std::string OPRN_BATCH_UPDATE_RECENT_SHOW = "batch_update_recent_show";
const std::string OPRN_QUERY_HIDDEN = "query_hidden";
const std::string OPRN_STORE_FORM_ID = "store_form_id";
const std::string OPRN_REMOVE_FORM_ID = "remove_form_id";
const std::string OPRN_ALBUM_ADD_PHOTOS = "add_photos";
const std::string OPRN_ALBUM_REMOVE_PHOTOS = "remove_photos";
const std::string OPRN_RECOVER_PHOTOS = "recover_photos";
// Delete non-trashed photos directly from system for api9 MediaLibrary.delete compatibility
const std::string OPRN_COMPAT_DELETE_PHOTOS = "compat_delete_photos_permanently";
const std::string OPRN_DELETE_BY_TOOL = "delete_by_tool";
const std::string OPRN_SET_USER_COMMENT = "set_user_comment";
const std::string OPRN_COMMIT_EDIT = "operation_commit_edit";
const std::string OPRN_REVERT_EDIT = "operation_revert_edit";
const std::string OPRN_ORDER_ALBUM = "order_album";
const std::string OPRN_PORTRAIT_DISPLAY_LEVEL = "display_level";
const std::string OPRN_PORTRAIT_IS_ME = "is_me";
const std::string OPRN_PORTRAIT_ALBUM_NAME = "album_name";
const std::string OPRN_PORTRAIT_MERGE_ALBUM = "merge_album";
const std::string OPRN_HIGHLIGHT_ALBUM_NAME = "highlight_name";
const std::string OPRN_HIGHLIGHT_COVER_URI = "highlight_cover_uri";
const std::string OPRN_HIGHLIGHT_SUBTITLE = "highlight_subtitle";
const std::string OPRN_RELATIONSHIP = "relationship";
const std::string OPRN_QUERY_HIGHLIGHT_DIRECTORY_SIZE = "query_highlight_directory_size";
const std::string OPRN_DISMISS_ASSET = "dismiss_asset";
const std::string UPDATE_DISMISS_ASSET = "dismiss_asset_update";
const std::string OPRN_PORTRAIT_COVER_URI = "cover_uri";
const std::string OPRN_SUBMIT_CACHE = "operation_submit_cache";
const std::string OPRN_ADD_IMAGE = "add_image";
const std::string OPRN_PROCESS_IMAGE = "process_image";
const std::string OPRN_SET_LOCATION = "set_location";
const std::string OPRN_SET_PHOTO_QUALITY = "set_photo_quality";
const std::string OPRN_CANCEL_PROCESS_IMAGE = "cancel_process_image";
const std::string OPRN_MOVING_PHOTO_SCAN = "moving_photo_scan";
const std::string OPRN_DEGENERATE_MOVING_PHOTO = "degenerate_moving_photo";
const std::string OPRN_START_GENERATE_THUMBNAILS = "start_generate_thumbnails";
const std::string OPRN_STOP_GENERATE_THUMBNAILS = "stop_generate_thumbnails";
const std::string OPRN_GENERATE_THUMBNAILS_RESTORE = "generate_thumbnails_restore";
const std::string OPRN_RESTORE_INVALID_HDC_CLOUD_DATA_POS = "RESTORE_INVALID_HDC_CLOUD_DATA_POS";
const std::string OPRN_LOCAL_THUMBNAIL_GENERATION = "local_thumbnail_generation";
const std::string OPRN_ADD_FILTERS = "add_filters";
const std::string OPRN_DISCARD_CAMERA_PHOTO = "discard_camera_photo";
const std::string OPRN_SAVE_CAMERA_PHOTO = "save_camera_photo";
const std::string OPRN_SAVE_PICTURE = "save_picture";
const std::string OPRN_CLONE_ASSET = "clone_asset";
const std::string OPRN_REMOVE_MSC_TASK = "remove_msc_task"; // remove multistages capture task
const std::string OPRN_GROUP_DISMISS = "dismiss";
const std::string OPRN_GROUP_ALBUM_NAME = "group_album_name";
const std::string OPRN_GROUP_COVER_URI = "group_cover_uri";
const std::string OPRN_SCAN_WITHOUT_ALBUM_UPDATE = "scan_without_album_update";
const std::string OPRN_ADD_LOWQUALITY_IMAGE = "add_lowquality_image";
const std::string OPRN_SET_VIDEO_ENHANCEMENT_ATTR = "set_video_enhancement_attr";
const std::string OPRN_FIND_ALL_DUPLICATE_ASSETS = "all_duplicate_assets";
const std::string URI_FIND_ALL_DUPLICATE_ASSETS = "/" + OPRN_FIND_ALL_DUPLICATE_ASSETS;
const std::string OPRN_FIND_ALL_DUPLICATE_ASSETS_TO_DELETE = "can_del_duplicate_assets";
const std::string URI_FIND_ALL_DUPLICATE_ASSETS_TO_DELETE = "/" + OPRN_FIND_ALL_DUPLICATE_ASSETS_TO_DELETE;
const std::string OPRN_UPDATE_SUPPORTED_WATERMARK_TYPE = "update_supported_watermark_type";
const std::string OPRN_UPDATE_HAS_APPLINK = "update_supported_has_applink";
const std::string OPRN_UPDATE_APPLINK = "update_supported_applink";
const std::string OPRN_QUERY_RAW_ANALYSIS_ALBUM = "query_raw_analysis_album";
// Asset operations constants
const std::string MEDIA_FILEOPRN = "file_operation";
const std::string MEDIA_PHOTOOPRN = "photo_operation";
const std::string MEDIA_AUDIOOPRN = "audio_operation";
const std::string MEDIA_APP_URI_PERMISSIONOPRN = "app_uri_permission_operation";
const std::string MEDIA_DOCUMENTOPRN = "document_operation";
const std::string MEDIA_FILEOPRN_CREATEASSET = "create_asset";
const std::string MEDIA_FILEOPRN_MODIFYASSET = "modify_asset";
const std::string MEDIA_FILEOPRN_DELETEASSET = "delete_asset";
const std::string MEDIA_FILEOPRN_TRASHASSET = "trash_asset";
const std::string MEDIA_FILEOPRN_OPENASSET = "open_asset";
const std::string MEDIA_FILEOPRN_CLOSEASSET = "close_asset";
const std::string PHOTO_TRANSCODE_OPERATION = "photo_transcode_operation";
const std::string OPRN_TRANSCODE_HEIF = "oprn_transcode_heif";
const std::string MEDIA_FILEOPRN_OPEN_DB_DFX = "open_db_dfx";

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
const std::string MTH_AND_YEAR_ASTC = "month_and_year_astc";

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

//UriPermission operations constants
const std::string CHECK_URI_PERMISSION = "phaccess_checkuripermission";
const std::string GRANT_URI_PERMISSION = "phaccess_granturipermission";

// Direcotry operations constants
const std::string MEDIA_DIROPRN = "dir_operation";
const std::string MEDIA_DIROPRN_DELETEDIR = "delete_dir";
const std::string MEDIA_DIROPRN_CHECKDIR_AND_EXTENSION = "check_dir_and_extension";
const std::string MEDIA_DIROPRN_FMS_CREATEDIR = "fms_create_dir";
const std::string MEDIA_DIROPRN_FMS_DELETEDIR = "fms_delete_dir";
const std::string MEDIA_DIROPRN_FMS_TRASHDIR = "fms_trash_dir";
const std::string MEDIA_QUERYOPRN_QUERYVOLUME = "query_media_volume";

// Query editData exists
const std::string MEDIA_QUERYOPRN_QUERYEDITDATA = "query_edit_data";

// Query moving photo video ready
const std::string MEDIA_QUERY_OPRN_MOVING_PHOTO_VIDEO_READY = "query_moving_photo_video_ready";

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
const std::string URI_DELETE_AUDIO = MEDIALIBRARY_DATA_URI + "/" + MEDIA_AUDIOOPRN + "/" + OPRN_DELETE;

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
const std::string PAH_ANA_MAP = "phaccess_ana_map_operation";
const std::string PAH_ANA_OCR = "phaccess_ana_ocr_operation";
const std::string PAH_ANA_ATTS = "phaccess_ana_atts_operation";
const std::string PAH_ANA_VIDEO_ATTS = "phaccess_ana_video_atts_operation";
const std::string PAH_ANA_LABEL = "phaccess_ana_label_operation";
const std::string PAH_ANA_VIDEO_LABEL = "phaccess_ana_video_label_operation";
const std::string PAH_ANA_FACE = "phaccess_ana_face_operation";
const std::string PAH_ANA_FACE_TAG = "phaccess_ana_face_tag_operation";
const std::string PAH_ANA_OBJECT = "phaccess_ana_object_operation";
const std::string PAH_ANA_RECOMMENDATION = "phaccess_ana_recommendation_operation";
const std::string PAH_ANA_SEGMENTATION = "phaccess_ana_segmentation_operation";
const std::string PAH_ANA_COMPOSITION = "phaccess_ana_composition_operation";
const std::string PAH_ANA_HEAD = "phaccess_ana_head_operation";
const std::string PAH_ANA_AFFECTIVE = "phaccess_ana_affective_operation";
const std::string PAH_ANA_POSE = "phaccess_ana_pose_operation";
const std::string PAH_ANA_SALIENCY = "phaccess_ana_sal_operation";
const std::string PAH_FORM_MAP = "phaccess_store_form_operation";
const std::string PAH_ANA_TOTAL = "phaccess_ana_total_operation";
const std::string PAH_ANA_ADDRESS = "phaccess_ana_address_operation";
const std::string PAH_ANA_ADDRESS_ASSETS = "phaccess_ana_address_assets_operation";
const std::string PAH_ANA_ADDRESS_ASSETS_ACTIVE = "phaccess_ana_address_assets_active_operation";
const std::string PAH_GEO_PHOTOS = "phaccess_geo_photos_operation";
const std::string PAH_CONVERT_PHOTOS = "phaccess_convert_photos_operation";
const std::string PAH_MULTISTAGES_CAPTURE = "phaccess_multistages_capture_operation";
const std::string PAH_HIGHLIGHT_COVER = "phaccess_highlight_cover_operation";
const std::string PAH_HIGHLIGHT_PLAY = "phaccess_highlight_play_operation";
const std::string PAH_HIGHLIGHT_ALBUM = "phaccess_highlight_album_operation";
const std::string PAH_HIGHLIGHT_DELETE = "phaccess_highlight_delete";
const std::string PAH_HIGHLIGHT_ADD_ASSETS = "phaccess_highlight_add_assets";
const std::string PAH_BATCH_THUMBNAIL_OPERATE = "phaccess_batch_thumbnail_operation";
const std::string PAH_BACKUP_POSTPROCESS = "phaccess_backup_postprocess";
const std::string SEARCH_INDEX_CONSTRUCTION_STATUS = "phaccess_search_index_construction_operation";
const std::string PAH_ANA_MULTI_CROP = "phaccess_ana_multi_crop_operation";
const std::string PAH_ANA_ASSET_SD = "tab_analysis_asset_sd_map";
const std::string PAH_ANA_ALBUM_ASSET = "tab_analysis_album_asset_map";
const std::string PAH_ANA_FOREGROUND = "phaccess_ana_foreground_operation";
// PhotoAccessHelper photo operation constants
const std::string PAH_CREATE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_CREATE;
const std::string PAH_SYS_CREATE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_SYS_CREATE;
const std::string PAH_CREATE_PHOTO_COMPONENT = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_CREATE_COMPONENT;
const std::string PAH_CLOSE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_CLOSE;
const std::string PAH_UPDATE_PHOTO = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_UPDATE;
const std::string PAH_UPDATE_PHOTO_COMPONENT = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" +
    OPRN_SAVE_CAMERA_PHOTO_COMPONENT;
const std::string PAH_TRASH_PHOTO = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_TRASH;
const std::string PAH_SYS_TRASH_PHOTO = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_SYS_TRASH;
const std::string PAH_QUERY_PHOTO = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_QUERY;
const std::string PAH_EDIT_USER_COMMENT_PHOTO = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_SET_USER_COMMENT;
const std::string PAH_HIDE_PHOTOS = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_HIDE;
const std::string PAH_SUBMIT_CACHE = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_SUBMIT_CACHE;
const std::string PAH_ADD_FILTERS = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_ADD_FILTERS;
const std::string PAH_BATCH_UPDATE_FAVORITE = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_BATCH_UPDATE_FAV;
const std::string PAH_BATCH_UPDATE_USER_COMMENT =
    MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_BATCH_UPDATE_USER_COMMENT;
const std::string PAH_BATCH_UPDATE_RECENT_SHOW =
    MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_BATCH_UPDATE_RECENT_SHOW;
const std::string PAH_BATCH_UPDATE_OWNER_ALBUM_ID =
    MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_BATCH_UPDATE_OWNER_ALBUM_ID;
const std::string PAH_GET_ANALYSIS_INDEX = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_ANALYSIS_INDEX;
const std::string PAH_DISCARD_CAMERA_PHOTO = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_DISCARD_CAMERA_PHOTO;
const std::string PAH_SAVE_CAMERA_PHOTO = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_SAVE_CAMERA_PHOTO;
const std::string PAH_SCAN_WITHOUT_ALBUM_UPDATE = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" +
    OPRN_SCAN_WITHOUT_ALBUM_UPDATE;
const std::string PATH_SAVE_PICTURE = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_SAVE_PICTURE;
const std::string PAH_FIND_ALL_DUPLICATE_ASSETS = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO +
    URI_FIND_ALL_DUPLICATE_ASSETS;
const std::string PAH_FIND_DUPLICATE_ASSETS_TO_DELETE = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO +
    URI_FIND_ALL_DUPLICATE_ASSETS_TO_DELETE;
const std::string PAH_CLONE_ASSET = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_CLONE_ASSET;
const std::string PAH_CUSTOM_RESTORE = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_CUSTOM_RESTORE;
const std::string PAH_CUSTOM_RESTORE_CANCEL =
    MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" + OPRN_CUSTOM_RESTORE_CANCEL;
const std::string PAH_UPDATE_PHOTO_SUPPORTED_WATERMARK_TYPE = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" +
    OPRN_UPDATE_SUPPORTED_WATERMARK_TYPE;
const std::string PAH_UPDATE_HAS_APPLINK = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" +
    OPRN_UPDATE_HAS_APPLINK;
const std::string PAH_UPDATE_APPLINK = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" +
    OPRN_UPDATE_APPLINK;

// MultiStages capture related operation uri
const std::string PAH_SET_PHOTO_QUALITY = MEDIALIBRARY_DATA_URI + "/ "+ PAH_PHOTO + "/" + OPRN_SET_PHOTO_QUALITY;
const std::string PAH_PROCESS_IMAGE = MEDIALIBRARY_DATA_URI + "/" + PAH_MULTISTAGES_CAPTURE + "/" + OPRN_PROCESS_IMAGE;
const std::string PAH_ADD_IMAGE = MEDIALIBRARY_DATA_URI + "/" + PAH_MULTISTAGES_CAPTURE + "/" + OPRN_ADD_IMAGE;
const std::string PAH_SET_LOCATION = MEDIALIBRARY_DATA_URI + "/" + PAH_MULTISTAGES_CAPTURE + "/" + OPRN_SET_LOCATION;
const std::string PAH_CANCEL_PROCESS_IMAGE =
    MEDIALIBRARY_DATA_URI + "/" + PAH_MULTISTAGES_CAPTURE + "/" + OPRN_CANCEL_PROCESS_IMAGE;
const std::string PAH_REMOVE_MSC_TASK =
    MEDIALIBRARY_DATA_URI + "/" + PAH_MULTISTAGES_CAPTURE + "/" + OPRN_REMOVE_MSC_TASK;

// Video
const std::string PAH_VIDEO = "video_operation";
 
// Video
const std::string PAH_SET_VIDEO_ENHANCEMENT_ATTR =
    MEDIALIBRARY_DATA_URI + "/" + PAH_VIDEO + "/" + OPRN_SET_VIDEO_ENHANCEMENT_ATTR;

// Generate thumbnails in batches operation uri
const std::string PAH_START_GENERATE_THUMBNAILS =
    MEDIALIBRARY_DATA_URI + "/" + PAH_BATCH_THUMBNAIL_OPERATE + "/" + OPRN_START_GENERATE_THUMBNAILS;
const std::string PAH_STOP_GENERATE_THUMBNAILS =
    MEDIALIBRARY_DATA_URI + "/" + PAH_BATCH_THUMBNAIL_OPERATE + "/" + OPRN_STOP_GENERATE_THUMBNAILS;
const std::string PAH_ADD_LOWQUALITY_IMAGE = MEDIALIBRARY_DATA_URI + "/" +
    PAH_MULTISTAGES_CAPTURE + "/" + OPRN_ADD_LOWQUALITY_IMAGE;
    
// Generate thumbnails after clone or upgrade restore operation uri
const std::string PAH_GENERATE_THUMBNAILS_RESTORE =
    MEDIALIBRARY_DATA_URI + "/" + PAH_BATCH_THUMBNAIL_OPERATE + "/" + OPRN_GENERATE_THUMBNAILS_RESTORE;

// Generate local thumbnail from cloud trigger
const std::string PAH_GENERATE_LOCAL_THUMBNAIL =
    MEDIALIBRARY_DATA_URI + "/" + PAH_BATCH_THUMBNAIL_OPERATE + "/" + OPRN_LOCAL_THUMBNAIL_GENERATION;

// restore hdc cloud data invalidated by backup
const std::string PAH_RESTORE_INVALID_HDC_CLOUD_DATA_POS =
    MEDIALIBRARY_DATA_URI + "/" + PAH_BACKUP_POSTPROCESS + "/" + OPRN_RESTORE_INVALID_HDC_CLOUD_DATA_POS;

const std::string PAH_QUERY_ANA_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ALBUM + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_PHOTO_MAP = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_MAP + "/" + OPRN_QUERY;
const std::string PAH_INSERT_ANA_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ALBUM + "/" + OPRN_CREATE;
const std::string PAH_UPDATE_ANA_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ALBUM + "/" + OPRN_UPDATE;
const std::string PAH_INSERT_ANA_PHOTO_MAP = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_MAP + "/" + OPRN_CREATE;
const std::string PAH_QUERY_ORDER_ANA_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_MAP + "/" + OPRN_QUERY_ORDER;
const std::string PAH_UPDATE_ORDER_ANA_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_MAP + "/" + OPRN_UPDATE_ORDER;

const std::string PAH_QUERY_ANA_OCR = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_OCR + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_ATTS = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ATTS + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_VIDEO_ATTS = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_VIDEO_ATTS + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_LABEL = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_LABEL + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_VIDEO_LABEL = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_VIDEO_LABEL + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_FACE = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_FACE + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_FACE_TAG = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_FACE_TAG + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_OBJECT = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_OBJECT + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_RECOMMENDATION = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_RECOMMENDATION + "/" +
    OPRN_QUERY;
const std::string PAH_QUERY_ANA_SEGMENTATION = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_SEGMENTATION + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_COMPOSITION = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_COMPOSITION + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_HEAD = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_HEAD + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_AFFECTIVE = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_AFFECTIVE + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_POSE = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_POSE + "/" + OPRN_QUERY;
const std::string PAH_STORE_FORM_MAP = MEDIALIBRARY_DATA_URI + "/" + PAH_FORM_MAP + "/" + OPRN_STORE_FORM_ID;
const std::string PAH_REMOVE_FORM_MAP = MEDIALIBRARY_DATA_URI + "/" + PAH_FORM_MAP + "/" + OPRN_REMOVE_FORM_ID;
const std::string PAH_QUERY_ANA_SAL = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_SALIENCY + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_ADDRESS = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_ADDRESS + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_ADDRESS_ASSETS = MEDIALIBRARY_DATA_URI + "/" +
    PAH_ANA_ADDRESS_ASSETS + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_ADDRESS_ASSETS_ACTIVE = MEDIALIBRARY_DATA_URI + "/" +
    PAH_ANA_ADDRESS_ASSETS_ACTIVE + "/" + OPRN_QUERY;
const std::string PAH_QUERY_GEO_PHOTOS = MEDIALIBRARY_DATA_URI + "/" + PAH_GEO_PHOTOS + "/" + OPRN_QUERY;
const std::string PAH_QUERY_CONVERT_PHOTOS = MEDIALIBRARY_DATA_URI + "/" + PAH_CONVERT_PHOTOS + "/" + OPRN_QUERY;
const std::string PAH_QUERY_HIGHLIGHT_COVER = MEDIALIBRARY_DATA_URI + "/" + PAH_HIGHLIGHT_COVER + "/" + OPRN_QUERY;
const std::string PAH_QUERY_HIGHLIGHT_PLAY = MEDIALIBRARY_DATA_URI + "/" + PAH_HIGHLIGHT_PLAY + "/" + OPRN_QUERY;
const std::string PAH_QUERY_HIGHLIGHT_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_HIGHLIGHT_ALBUM + "/" + OPRN_QUERY;
const std::string PAH_QUERY_ANA_TOTAL = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_TOTAL + "/" + OPRN_QUERY;
const std::string PAH_QUERY_MULTI_CROP = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_MULTI_CROP + "/" + OPRN_QUERY;
const std::string PAH_UPDATE_ANA_FACE = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_FACE + "/" + OPRN_UPDATE;
const std::string PAH_DELETE_HIGHLIGHT_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_HIGHLIGHT_DELETE + "/" + OPRN_DELETE;
const std::string PAH_INSERT_HIGHLIGHT_ALBUM = MEDIALIBRARY_DATA_URI + "/" + PAH_HIGHLIGHT_ADD_ASSETS;
const std::string PAH_QUERY_ANA_FOREGROUND = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_FOREGROUND + "/" + OPRN_QUERY;

// PhotoAccessHelper moving photo
const std::string PAH_MOVING_PHOTO_SCAN = MEDIALIBRARY_DATA_URI + "/" + MEDIA_MOVING_PHOTO_OPRN_KEYWORD + "/" +
    OPRN_MOVING_PHOTO_SCAN;
const std::string PAH_DEGENERATE_MOVING_PHOTO = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/" +
    OPRN_DEGENERATE_MOVING_PHOTO;

// Miscellaneous operation constants
const std::string MISC_OPERATION = "miscellaneous_operation";

const std::string OPRN_LOG_MOVING_PHOTO = "log_moving_photo";
const std::string OPRN_QUERY_ACTIVE_USER_ID = "query_active_user_id";

const std::string LOG_MOVING_PHOTO = MEDIALIBRARY_DATA_URI + "/" + MISC_OPERATION + "/" + OPRN_LOG_MOVING_PHOTO;
const std::string QUERY_ACTIVE_USER_ID = MEDIALIBRARY_DATA_URI + "/" + MISC_OPERATION + "/" + OPRN_QUERY_ACTIVE_USER_ID;

const std::string OPRN_FINISH_REQUEST_PICTURE = "finish_request_picture";
const std::string PAH_FINISH_REQUEST_PICTURE = MEDIALIBRARY_DATA_URI + "/" + PAH_PHOTO + "/"
    + OPRN_FINISH_REQUEST_PICTURE;

const std::string MEDIATYPE_DIRECTORY_OBJ = "MediaTypeDirectory";

const std::string TAB_OLD_PHOTO = "tab_old_photos_operation";
const std::string QUERY_TAB_OLD_PHOTO = MEDIALIBRARY_DATA_URI + "/" + TAB_OLD_PHOTO + "/" + OPRN_QUERY;

const std::string TAB_FACARD_PHOTO = "tab_facard_photos_operation";
const std::string PAH_STORE_FACARD_PHOTO = MEDIALIBRARY_DATA_URI + "/" + TAB_FACARD_PHOTO + "/" + OPRN_STORE_FORM_ID;
const std::string PAH_REMOVE_FACARD_PHOTO = MEDIALIBRARY_DATA_URI + "/" + TAB_FACARD_PHOTO + "/" + OPRN_REMOVE_FORM_ID;

const std::string ASSET_ALBUM_OPERATION = "tab_asset_and_album_operation";

} // namespace Media
} // namespace OHOS

#endif // OHOS_FILEMANAGEMENT_USERFILEMGR_URI_H
