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

export enum PhotoType {
    IMAGE = 1,
    VIDEO
}

export enum PhotoSubtype {
    DEFAULT = 0,
    SCREENSHOT = 1,
    MOVING_PHOTO = 3,
    BURST = 4,
}

export enum DynamicRangeType {
    SDR = 0,
    HDR = 1
}

export enum PositionType {
    LOCAL = 1 << 0,
    CLOUD = 1 << 1
}

export enum AnalysisType {
    ANALYSIS_AESTHETICS_SCORE = 0,
    ANALYSIS_LABEL,
    ANALYSIS_OCR,
    ANALYSIS_FACE,
    ANALYSIS_OBJECT,
    ANALYSIS_RECOMMENDATION,
    ANALYSIS_SEGMENTATION,
    ANALYSIS_COMPOSITION,
    ANALYSIS_SALIENCY,
    ANALYSIS_DETAIL_ADDRESS,
    ANALYSIS_HUMAN_FACE_TAG,
    ANALYSIS_HEAD_POSITION,
    ANALYSIS_BONE_POSE,
    ANALYSIS_VIDEO_LABEL,
    ANALYSIS_HIGHLIGHT,
    ANALYSIS_MULTI_CROP
}

export enum RecommendationType {
    QR_OR_BAR_CODE = 1,
    QR_CODE = 2,
    BAR_CODE = 3,
    ID_CARD = 4,
    PROFILE_PICTURE = 5,
    PASSPORT = 6,
    BANK_CARD = 7,
    DRIVER_LICENSE = 8,
    DRIVING_LICENSE = 9,
    FEATURED_SINGLE_PORTRAIT = 10
}

export enum DeliveryMode {
    FAST_MODE = 0,
    HIGH_QUALITY_MODE = 1,
    BALANCE_MODE = 2
}

export enum CompatibleMode {
    ORIGINAL_FORMAT_MODE = 0,
    COMPATIBLE_FORMAT_MODE = 1
}

export enum SourceMode {
    ORIGINAL_MODE = 0,
    EDITED_MODE = 1
}

export enum PhotoPermissionType {
    TEMPORARY_READ_IMAGEVIDEO = 0,
    PERSISTENT_READ_IMAGEVIDEO = 1
}

export enum HideSensitiveType {
    HIDE_LOCATION_AND_SHOOTING_PARAM = 0,
    HIDE_LOCATION_ONLY = 1,
    HIDE_SHOOTING_PARAM_ONLY = 2,
    NO_HIDE_SENSITIVE_TYPE = 3
}

export enum AuthorizationMode {
    SHORT_TIME_AUTHORIZATION = 0
}

export enum CompleteButtonText {
    TEXT_DONE = 0,
    TEXT_SEND = 1,
    TEXT_ADD = 2,
}

export enum WatermarkType {
    DEFAULT = 0,
    BRAND_COMMON = 1,
    COMMON = 2,
    BRAND = 3,
}

export enum HiddenPhotosDisplayMode {
    ASSETS_MODE,
    ALBUMS_MODE
}

export enum AlbumType {
    USER = 0,
    SYSTEM = 1024,
    SMART = 4096
}

export enum AlbumSubtype {
    USER_GENERIC = 1,
    FAVORITE = 1025,
    VIDEO,
    HIDDEN,
    TRASH,
    SCREENSHOT,
    CAMERA,
    IMAGE = 1031,
    CLOUD_ENHANCEMENT = 1032,
    SOURCE_GENERIC = 2049,
    CLASSIFY = 4097,
    GEOGRAPHY_LOCATION = 4099,
    GEOGRAPHY_CITY,
    SHOOTING_MODE,
    PORTRAIT,
    GROUP_PHOTO,
    HIGHLIGHT = 4104,
    HIGHLIGHT_SUGGESTIONS,
    ANY = 2147483647
}

export enum RequestPhotoType {
    REQUEST_ALL_THUMBNAILS = 0,
    REQUEST_FAST_THUMBNAIL,
    REQUEST_QUALITY_THUMBNAIL
}

export enum NotifyType {
    NOTIFY_ADD,
    NOTIFY_UPDATE,
    NOTIFY_REMOVE,
    NOTIFY_ALBUM_ADD_ASSET,
    NOTIFY_ALBUM_REMOVE_ASSET
}

export enum ResourceType {
    IMAGE_RESOURCE = 1,
    VIDEO_RESOURCE = 2,
    PHOTO_PROXY = 3,
    PRIVATE_MOVING_PHOTO_RESOURCE = 4
}

export enum ImageFileType {
    JPEG = 1,
    HEIF = 2
}

export enum MovingPhotoEffectMode {
    DEFAULT = 0,
    BOUNCE_PLAY = 1,
    LOOP_PLAY = 2,
    LONG_EXPOSURE = 3,
    MULTI_EXPOSURE = 4,
    CINEMA_GRAPH = 5,
    IMAGE_ONLY = 10
}

export enum VideoEnhancementType {
    QUALITY_ENHANCEMENT_LOCAL = 0,
    QUALITY_ENHANCEMENT_CLOUD = 1,
    QUALITY_ENHANCEMENT_LOCAL_AND_CLOUD = 2
}

export enum HighlightAlbumInfoType {
    COVER_INFO = 0,
    PLAY_INFO
}

export enum HighlightUserActionType {
    INSERTED_PIC_COUNT = 0,
    REMOVED_PIC_COUNT,
    SHARED_SCREENSHOT_COUNT,
    SHARED_COVER_COUNT,
    RENAMED_COUNT,
    CHANGED_COVER_COUNT,
    RENDER_VIEWED_TIMES = 100,
    RENDER_VIEWED_DURATION,
    ART_LAYOUT_VIEWED_TIMES,
    ART_LAYOUT_VIEWED_DURATION
}

export enum ThumbnailType {
    LCD = 1,
    THM = 2
}

export enum CloudEnhancementTaskStage {
    TASK_STAGE_EXCEPTION = -1,
    TASK_STAGE_PREPARING,
    TASK_STAGE_UPLOADING,
    TASK_STAGE_EXECUTING,
    TASK_STAGE_DOWNLOADING,
    TASK_STAGE_FAILED,
    TASK_STAGE_COMPLETED
}

export enum CloudEnhancementState {
    UNAVAILABLE = 0,
    AVAILABLE,
    EXECUTING,
    COMPLETED
}

export enum PhotoKeys {
    URI = 'uri',
    PHOTO_TYPE = 'media_type',
    DISPLAY_NAME = 'display_name',
    SIZE = 'size',
    DATE_ADDED = 'date_added',
    DATE_MODIFIED = 'date_modified',
    DURATION = 'duration',
    WIDTH = 'width',
    HEIGHT = 'height',
    DATE_TAKEN = 'date_taken',
    ORIENTATION = 'orientation',
    FAVORITE = 'is_favorite',
    TITLE = 'title',
    POSITION = 'position',
    DATE_TRASHED = 'date_trashed',
    HIDDEN = 'hidden',
    USER_COMMENT = 'user_comment',
    CAMERA_SHOT_KEY = 'camera_shot_key',
    DATE_YEAR = 'date_year',
    DATE_MONTH = 'date_month',
    DATE_DAY = 'date_day',
    PENDING = 'pending',
    DATE_ADDED_MS = 'date_added_ms',
    DATE_MODIFIED_MS = 'date_modified_ms',
    DATE_TRASHED_MS = 'date_trashed_ms',
    PHOTO_SUBTYPE = 'subtype',
    MOVING_PHOTO_EFFECT_MODE = 'moving_photo_effect_mode',
    DYNAMIC_RANGE_TYPE = 'dynamic_range_type',
    COVER_POSITION = 'cover_position',
    BURST_KEY = 'burst_key',
    THUMBNAIL_READY = 'thumbnail_ready',
    LCD_SIZE = 'lcd_size',
    THM_SIZE = 'thm_size',
    DETAIL_TIME = 'detail_time',
    DATE_TAKEN_MS = 'date_taken_ms',
    CE_AVAILABLE = 'ce_available',
    SUPPORTED_WATERMARK_TYPE = 'supported_watermark_type'
}

export enum AlbumKeys {
    URI = 'uri',
    ALBUM_NAME = 'album_name'
}

export enum DefaultChangeUri {
    DEFAULT_PHOTO_URI = 'file://media/Photo',
    DEFAULT_ALBUM_URI = 'file://media/PhotoAlbum',
    DEFAULT_HIDDEN_ALBUM_URI = 'file://media/HiddenAlbum'
}

export enum PhotoViewMIMETypes {
    MOVING_PHOTO_IMAGE_TYPE = 'image/movingPhoto'
}
