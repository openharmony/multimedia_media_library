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
#ifndef FRAMEWORKS_SERVICES_MEDIA_MTP_INCLUDE_MTP_CONSTANTS_H_
#define FRAMEWORKS_SERVICES_MEDIA_MTP_INCLUDE_MTP_CONSTANTS_H_
#include <vector>
#include <stdint.h>
#include <fcntl.h>

struct MtpFileRange {
    // file descriptor for file to transfer
    int fd;
    // offset in file for start of transfer
    loff_t offset;
    // number of bytes to transfer
    int64_t length;
    /*
     * MTP command ID for data header,
     * used only for MTP_SEND_FILE_WITH_HEADER
     */
    uint16_t command;
    /*
     * MTP transaction ID for data header,
     * used only for MTP_SEND_FILE_WITH_HEADER
     */
    uint32_t transaction_id;
};

struct EventMtp {
    // size of the event
    size_t length;
    // event data to send
    std::vector<uint8_t> data;
};

constexpr uint16_t MTP_STANDARD_VERSION = 100;

constexpr int32_t DEFAULT_STORAGE_ID = 1;
constexpr uint32_t MTP_ALL_HANDLE_ID = 0xFFFFFFFF;
constexpr uint32_t MTP_ALL_DEPTH = 0xFFFFFFFF;

// mtp Operations
constexpr uint16_t MTP_OPERATION_GET_DEVICE_INFO_CODE = 0x1001;
constexpr uint16_t MTP_OPERATION_OPEN_SESSION_CODE = 0x1002;
constexpr uint16_t MTP_OPERATION_CLOSE_SESSION_CODE = 0x1003;
constexpr uint16_t MTP_OPERATION_GET_STORAGE_IDS_CODE = 0x1004;
constexpr uint16_t MTP_OPERATION_GET_STORAGE_INFO_CODE = 0x1005;
constexpr uint16_t MTP_OPERATION_GET_NUM_OBJECTS_CODE = 0x1006;
constexpr uint16_t MTP_OPERATION_GET_OBJECT_HANDLES_CODE = 0x1007;
constexpr uint16_t MTP_OPERATION_GET_OBJECT_INFO_CODE = 0x1008;
constexpr uint16_t MTP_OPERATION_GET_OBJECT_CODE = 0x1009;
constexpr uint16_t MTP_OPERATION_GET_THUMB_CODE = 0x100A;
constexpr uint16_t MTP_OPERATION_DELETE_OBJECT_CODE = 0x100B;
constexpr uint16_t MTP_OPERATION_SEND_OBJECT_INFO_CODE = 0x100C;
constexpr uint16_t MTP_OPERATION_SEND_OBJECT_CODE = 0x100D;
constexpr uint16_t MTP_OPERATION_INITIATE_CAPTURE_CODE = 0x100E;
constexpr uint16_t MTP_OPERATION_FORMAT_STORE_CODE = 0x100F;
constexpr uint16_t MTP_OPERATION_RESET_DEVICE_CODE = 0x1010;
constexpr uint16_t MTP_OPERATION_SELF_TEST_CODE = 0x1011;
constexpr uint16_t MTP_OPERATION_SET_OBJECT_PROTECTION_CODE = 0x1012;
constexpr uint16_t MTP_OPERATION_POWER_DOWN_CODE = 0x1013;
constexpr uint16_t MTP_OPERATION_GET_DEVICE_PROP_DESC_CODE = 0x1014;
constexpr uint16_t MTP_OPERATION_GET_DEVICE_PROP_VALUE_CODE = 0x1015;
constexpr uint16_t MTP_OPERATION_SET_DEVICE_PROP_VALUE_CODE = 0x1016;
constexpr uint16_t MTP_OPERATION_RESET_DEVICE_PROP_VALUE_CODE = 0x1017;
constexpr uint16_t MTP_OPERATION_TERMINATE_OPEN_CAPTURE_CODE = 0x1018;
constexpr uint16_t MTP_OPERATION_MOVE_OBJECT_CODE = 0x1019;
constexpr uint16_t MTP_OPERATION_COPY_OBJECT_CODE = 0x101A;
constexpr uint16_t MTP_OPERATION_GET_PARTIAL_OBJECT_CODE = 0x101B;
constexpr uint16_t MTP_OPERATION_INITIATE_OPEN_CAPTURE_CODE = 0x101C;
constexpr uint16_t MTP_OPERATION_GET_OBJECT_PROPS_SUPPORTED_CODE = 0x9801;
constexpr uint16_t MTP_OPERATION_GET_OBJECT_PROP_DESC_CODE = 0x9802;
constexpr uint16_t MTP_OPERATION_GET_OBJECT_PROP_VALUE_CODE = 0x9803;
constexpr uint16_t MTP_OPERATION_SET_OBJECT_PROP_VALUE_CODE = 0x9804;
constexpr uint16_t MTP_OPERATION_GET_OBJECT_PROP_LIST_CODE = 0x9805;
constexpr uint16_t MTP_OPERATION_SET_OBJECT_PROP_LIST_CODE = 0x9806;
constexpr uint16_t MTP_OPERATION_GET_INTERDEPENDENT_PROPDESC_CODE = 0x9807;
constexpr uint16_t MTP_OPERATION_SEND_OBJECT_PROP_LIST_CODE = 0x9808;
constexpr uint16_t MTP_OPERATION_GET_OBJECT_REFERENCES_CODE = 0x9810;
constexpr uint16_t MTP_OPERATION_SET_OBJECT_REFERENCES_CODE = 0x9811;
constexpr uint16_t MTP_OPERATION_SKIP_CODE = 0x9820;

// MTP Device Property
constexpr uint16_t MTP_DEVICE_PROPERTY_UNDEFINED_CODE = 0x5000;
constexpr uint16_t MTP_DEVICE_PROPERTY_BATTERY_LEVEL_CODE = 0x5001;
constexpr uint16_t MTP_DEVICE_PROPERTY_FUNCTIONAL_MODE_CODE = 0x5002;
constexpr uint16_t MTP_DEVICE_PROPERTY_IMAGE_SIZE_CODE = 0x5003;
constexpr uint16_t MTP_DEVICE_PROPERTY_COMPRESSION_SETTING_CODE = 0x5004;
constexpr uint16_t MTP_DEVICE_PROPERTY_WHITE_BALANCE_CODE = 0x5005;
constexpr uint16_t MTP_DEVICE_PROPERTY_RGB_GAIN_CODE = 0x5006;
constexpr uint16_t MTP_DEVICE_PROPERTY_F_NUMBER_CODE = 0x5007;
constexpr uint16_t MTP_DEVICE_PROPERTY_FOCAL_LENGTH_CODE = 0x5008;
constexpr uint16_t MTP_DEVICE_PROPERTY_FOCUS_DISTANCE_CODE = 0x5009;
constexpr uint16_t MTP_DEVICE_PROPERTY_FOCUS_MODE_CODE = 0x500A;
constexpr uint16_t MTP_DEVICE_PROPERTY_EXPOSURE_METERING_MODE_CODE = 0x500B;
constexpr uint16_t MTP_DEVICE_PROPERTY_FLASH_MODE_CODE = 0x500C;
constexpr uint16_t MTP_DEVICE_PROPERTY_EXPOSURE_TIME_CODE = 0x500D;
constexpr uint16_t MTP_DEVICE_PROPERTY_EXPOSURE_PROGRAM_MODE_CODE = 0x500E;
constexpr uint16_t MTP_DEVICE_PROPERTY_EXPOSURE_INDEX_CODE = 0x500F;
constexpr uint16_t MTP_DEVICE_PROPERTY_EXPOSURE_BIAS_COMPENSATION_CODE = 0x5010;
constexpr uint16_t MTP_DEVICE_PROPERTY_DATETIME_CODE = 0x5011;
constexpr uint16_t MTP_DEVICE_PROPERTY_CAPTURE_DELAY_CODE = 0x5012;
constexpr uint16_t MTP_DEVICE_PROPERTY_STILL_CAPTURE_MODE_CODE = 0x5013;
constexpr uint16_t MTP_DEVICE_PROPERTY_CONTRAST_CODE = 0x5014;
constexpr uint16_t MTP_DEVICE_PROPERTY_SHARPNESS_CODE = 0x5015;
constexpr uint16_t MTP_DEVICE_PROPERTY_DIGITAL_ZOOM_CODE = 0x5016;
constexpr uint16_t MTP_DEVICE_PROPERTY_EFFECT_MODE_CODE = 0x5017;
constexpr uint16_t MTP_DEVICE_PROPERTY_BURST_NUMBER_CODE = 0x5018;
constexpr uint16_t MTP_DEVICE_PROPERTY_BURST_INTERVAL_CODE = 0x5019;
constexpr uint16_t MTP_DEVICE_PROPERTY_TIMELAPSE_NUMBER_CODE = 0x501A;
constexpr uint16_t MTP_DEVICE_PROPERTY_TIMELAPSE_INTERVAL_CODE = 0x501B;
constexpr uint16_t MTP_DEVICE_PROPERTY_FOCUS_METERING_MODE_CODE = 0x501C;
constexpr uint16_t MTP_DEVICE_PROPERTY_UPLOAD_URL_CODE = 0x501D;
constexpr uint16_t MTP_DEVICE_PROPERTY_ARTIST_CODE = 0x501E;
constexpr uint16_t MTP_DEVICE_PROPERTY_COPYRIGHT_INFO_CODE = 0x501F;
constexpr uint16_t MTP_DEVICE_PROPERTY_SYNCHRONIZATION_PARTNER_CODE = 0xD401;
constexpr uint16_t MTP_DEVICE_PROPERTY_DEVICE_FRIENDLY_NAME_CODE = 0xD402;
constexpr uint16_t MTP_DEVICE_PROPERTY_VOLUME_CODE = 0xD403;
constexpr uint16_t MTP_DEVICE_PROPERTY_SUPPORTED_FORMATS_ORDERED_CODE = 0xD404;
constexpr uint16_t MTP_DEVICE_PROPERTY_DEVICE_ICON_CODE = 0xD405;
constexpr uint16_t MTP_DEVICE_PROPERTY_PLAYBACK_RATE_CODE = 0xD410;
constexpr uint16_t MTP_DEVICE_PROPERTY_PLAYBACK_OBJECT_CODE = 0xD411;
constexpr uint16_t MTP_DEVICE_PROPERTY_PLAYBACK_CONTAINER_INDEX_CODE = 0xD412;
constexpr uint16_t MTP_DEVICE_PROPERTY_SESSION_INITIATOR_VERSION_INFO_CODE = 0xD406;
constexpr uint16_t MTP_DEVICE_PROPERTY_PERCEIVED_DEVICE_TYPE_CODE = 0xD407;

// MTP Object Format
constexpr uint16_t MTP_FORMAT_UNDEFINED_CODE = 0x3000; // Undefined
constexpr uint16_t MTP_FORMAT_ASSOCIATION_CODE = 0x3001; // associations (folders and directories)
constexpr uint16_t MTP_FORMAT_SCRIPT_CODE = 0x3002; // script files
constexpr uint16_t MTP_FORMAT_EXECUTABLE_CODE = 0x3003; // executable files
constexpr uint16_t MTP_FORMAT_TEXT_CODE = 0x3004; // text files
constexpr uint16_t MTP_FORMAT_HTML_CODE = 0x3005; // HTML files
constexpr uint16_t MTP_FORMAT_DPOF_CODE = 0x3006; // DPOF files
constexpr uint16_t MTP_FORMAT_AIFF_CODE = 0x3007; // AIFF audio files
constexpr uint16_t MTP_FORMAT_WAV_CODE = 0x3008; // WAV audio files
constexpr uint16_t MTP_FORMAT_MP3_CODE = 0x3009; // MP3 audio files
constexpr uint16_t MTP_FORMAT_AVI_CODE = 0x300A; // AVI video files
constexpr uint16_t MTP_FORMAT_MPEG_CODE = 0x300B; // MPEG video files
constexpr uint16_t MTP_FORMAT_ASF_CODE = 0x300C; // ASF files
// Unknown image files which are not specified in PTP specification
constexpr uint16_t MTP_FORMAT_DEFINED_CODE = 0x3800; // Unknown image files
constexpr uint16_t MTP_FORMAT_EXIF_JPEG_CODE = 0x3801; // JPEG image files
constexpr uint16_t MTP_FORMAT_TIFF_EP_CODE = 0x3802; // TIFF EP image files
constexpr uint16_t MTP_FORMAT_FLASHPIX_CODE = 0x3803;
constexpr uint16_t MTP_FORMAT_BMP_CODE = 0x3804; // BMP image files
constexpr uint16_t MTP_FORMAT_CIFF_CODE = 0x3805;
constexpr uint16_t MTP_FORMAT_GIF_CODE = 0x3807; // GIF image files
constexpr uint16_t MTP_FORMAT_JFIF_CODE = 0x3808; // JFIF image files
constexpr uint16_t MTP_FORMAT_CD_CODE = 0x3809;
constexpr uint16_t MTP_FORMAT_PICT_CODE = 0x380A; // PICT image files
constexpr uint16_t MTP_FORMAT_PNG_CODE = 0x380B; // PNG image files
constexpr uint16_t MTP_FORMAT_TIFF_CODE = 0x380D; // TIFF image files
constexpr uint16_t MTP_FORMAT_TIFF_IT_CODE = 0x380E;
constexpr uint16_t MTP_FORMAT_JP2_CODE = 0x380F; // JP2 files
constexpr uint16_t MTP_FORMAT_JPX_CODE = 0x3810; // JPX files
constexpr uint16_t MTP_FORMAT_UNDEFINED_FIRMWARE_CODE = 0xB802; // firmware files
constexpr uint16_t MTP_FORMAT_WINDOWS_IMAGE_FORMAT_CODE = 0xB881; // Windows image files
constexpr uint16_t MTP_FORMAT_UNDEFINED_AUDIO_CODE = 0xB900; // undefined audio files files
constexpr uint16_t MTP_FORMAT_WMA_CODE = 0xB901; // WMA audio files
constexpr uint16_t MTP_FORMAT_OGG_CODE = 0xB902; // OGG audio files
constexpr uint16_t MTP_FORMAT_AAC_CODE = 0xB903; // AAC audio files
constexpr uint16_t MTP_FORMAT_AUDIBLE_CODE = 0xB904; // Audible audio files
constexpr uint16_t MTP_FORMAT_FLAC_CODE = 0xB906; // FLAC audio files
constexpr uint16_t MTP_FORMAT_UNDEFINED_VIDEO_CODE = 0xB980; // undefined video files
constexpr uint16_t MTP_FORMAT_WMV_CODE = 0xB981; // WMV video files
constexpr uint16_t MTP_FORMAT_MP4_CONTAINER_CODE = 0xB982; // MP4 files
constexpr uint16_t MTP_FORMAT_MP2_CODE = 0xB983; // MP2 files
constexpr uint16_t MTP_FORMAT_3GP_CONTAINER_CODE = 0xB984; // 3GP files

constexpr uint16_t MTP_FORMAT_UNDEFINED_COLLECTION_CODE = 0xBA00; // undefined collections
constexpr uint16_t MTP_FORMAT_ABSTRACT_MULTIMEDIA_ALBUM_CODE = 0xBA01; // multimedia albums
constexpr uint16_t MTP_FORMAT_ABSTRACT_IMAGE_ALBUM_CODE = 0xBA02; // image albums
constexpr uint16_t MTP_FORMAT_ABSTRACT_AUDIO_ALBUM_CODE = 0xBA03; // audio albums
constexpr uint16_t MTP_FORMAT_ABSTRACT_VIDEO_ALBUM_CODE = 0xBA04; // video albums
constexpr uint16_t MTP_FORMAT_ABSTRACT_AUDIO_VIDEO_PLAYLIST_CODE = 0xBA05; // abstract AV playlists
constexpr uint16_t MTP_FORMAT_ABSTRACT_CONTACT_GROUP_CODE = 0xBA06;
constexpr uint16_t MTP_FORMAT_ABSTRACT_MESSAGE_FOLDER_CODE = 0xBA07;
constexpr uint16_t MTP_FORMAT_ABSTRACT_CHAPTERED_PRODUCTION_CODE = 0xBA08;
constexpr uint16_t MTP_FORMAT_ABSTRACT_AUDIO_PLAYLIST_CODE = 0xBA09; // abstract audio playlists
constexpr uint16_t MTP_FORMAT_ABSTRACT_VIDEO_PLAYLIST_CODE = 0xBA0A; // abstract video playlists
constexpr uint16_t MTP_FORMAT_ABSTRACT_MEDIACAST_CODE = 0xBA0B; // abstract mediacasts
constexpr uint16_t MTP_FORMAT_WPL_PLAYLIST_CODE = 0xBA10; // WPL playlist files
constexpr uint16_t MTP_FORMAT_M3U_PLAYLIST_CODE = 0xBA11; // M3u playlist files
constexpr uint16_t MTP_FORMAT_MPL_PLAYLIST_CODE = 0xBA12; // MPL playlist files
constexpr uint16_t MTP_FORMAT_ASX_PLAYLIST_CODE = 0xBA13; // ASX playlist files
constexpr uint16_t MTP_FORMAT_PLS_PLAYLIST_CODE = 0xBA14; // PLS playlist files
constexpr uint16_t MTP_FORMAT_UNDEFINED_DOCUMENT_CODE = 0xBA80; // undefined document files
constexpr uint16_t MTP_FORMAT_ABSTRACT_DOCUMENT_CODE = 0xBA81; // abstract documents
constexpr uint16_t MTP_FORMAT_XML_DOCUMENT_CODE = 0xBA82; // XML documents
constexpr uint16_t MTP_FORMAT_MICROSOFT_WORD_DOCUMENT_CODE = 0xBA83; // MS Word documents
constexpr uint16_t MTP_FORMAT_MHT_COMPILED_HTML_DOCUMENT_CODE = 0xBA84;
constexpr uint16_t MTP_FORMAT_MICROSOFT_EXCEL_SPREADSHEET_CODE = 0xBA85; // MS Excel spreadsheets
constexpr uint16_t MTP_FORMAT_MICROSOFT_POWERPOINT_PRESENTATION_CODE = 0xBA86; // MS PowerPoint presentatiosn
constexpr uint16_t MTP_FORMAT_UNDEFINED_MESSAGE_CODE = 0xBB00;
constexpr uint16_t MTP_FORMAT_ABSTRACT_MESSAGE_CODE = 0xBB01;
constexpr uint16_t MTP_FORMAT_UNDEFINED_CONTACT_CODE = 0xBB80;
constexpr uint16_t MTP_FORMAT_ABSTRACT_CONTACT_CODE = 0xBB81;
constexpr uint16_t MTP_FORMAT_VCARD_2_CODE = 0xBB82;

// MTP Object Property
constexpr uint32_t MTP_PROPERTY_ALL_CODE = 0xFFFFFFFF;
constexpr uint16_t MTP_PROPERTY_STORAGE_ID_CODE = 0xDC01;
constexpr uint16_t MTP_PROPERTY_OBJECT_FORMAT_CODE = 0xDC02;
constexpr uint16_t MTP_PROPERTY_PROTECTION_STATUS_CODE = 0xDC03;
constexpr uint16_t MTP_PROPERTY_OBJECT_SIZE_CODE = 0xDC04;
constexpr uint16_t MTP_PROPERTY_ASSOCIATION_TYPE_CODE = 0xDC05;
constexpr uint16_t MTP_PROPERTY_ASSOCIATION_DESC_CODE = 0xDC06;
constexpr uint16_t MTP_PROPERTY_OBJECT_FILE_NAME_CODE = 0xDC07;
constexpr uint16_t MTP_PROPERTY_DATE_CREATED_CODE = 0xDC08;
constexpr uint16_t MTP_PROPERTY_DATE_MODIFIED_CODE = 0xDC09;
constexpr uint16_t MTP_PROPERTY_KEYWORDS_CODE = 0xDC0A;
constexpr uint16_t MTP_PROPERTY_PARENT_OBJECT_CODE = 0xDC0B;
constexpr uint16_t MTP_PROPERTY_ALLOWED_FOLDER_CONTENTS_CODE = 0xDC0C;
constexpr uint16_t MTP_PROPERTY_HIDDEN_CODE = 0xDC0D;
constexpr uint16_t MTP_PROPERTY_SYSTEM_OBJECT_CODE = 0xDC0E;
constexpr uint16_t MTP_PROPERTY_PERSISTENT_UID_CODE = 0xDC41;
constexpr uint16_t MTP_PROPERTY_SYNCID_CODE = 0xDC42;
constexpr uint16_t MTP_PROPERTY_PROPERTY_BAG_CODE = 0xDC43;
constexpr uint16_t MTP_PROPERTY_NAME_CODE = 0xDC44;
constexpr uint16_t MTP_PROPERTY_CREATED_BY_CODE = 0xDC45;
constexpr uint16_t MTP_PROPERTY_ARTIST_CODE = 0xDC46;
constexpr uint16_t MTP_PROPERTY_DATE_AUTHORED_CODE = 0xDC47;
constexpr uint16_t MTP_PROPERTY_DESCRIPTION_CODE = 0xDC48;
constexpr uint16_t MTP_PROPERTY_URL_REFERENCE_CODE = 0xDC49;
constexpr uint16_t MTP_PROPERTY_LANGUAG_LOCALE_CODE = 0xDC4A;
constexpr uint16_t MTP_PROPERTY_COPYRIGHT_INFORMATION_CODE = 0xDC4B;
constexpr uint16_t MTP_PROPERTY_SOURCE_CODE = 0xDC4C;
constexpr uint16_t MTP_PROPERTY_ORIGIN_LOCATION_CODE = 0xDC4D;
constexpr uint16_t MTP_PROPERTY_DATE_ADDED_CODE = 0xDC4E;
constexpr uint16_t MTP_PROPERTY_NO_CONSUMABLE_CODE = 0xDC4F;
constexpr uint16_t MTP_PROPERTY_CORRUP_UNPLAYABLE_CODE = 0xDC50;
constexpr uint16_t MTP_PROPERTY_PRODUCERSERIALNUMBER_CODE = 0xDC51;
constexpr uint16_t MTP_PROPERTY_REPRESENTATIVE_SAMPLE_FORMAT_CODE = 0xDC81;
constexpr uint16_t MTP_PROPERTY_REPRESENTATIVE_SAMPLE_SIZE_CODE = 0xDC82;
constexpr uint16_t MTP_PROPERTY_REPRESENTATIVE_SAMPLE_HEIGHT_CODE = 0xDC83;
constexpr uint16_t MTP_PROPERTY_REPRESENTATIVE_SAMPLE_WIDTH_CODE = 0xDC84;
constexpr uint16_t MTP_PROPERTY_REPRESENTATIVE_SAMPLE_DURATION_CODE = 0xDC85;
constexpr uint16_t MTP_PROPERTY_REPRESENTATIVE_SAMPLE_DATA_CODE = 0xDC86;
constexpr uint16_t MTP_PROPERTY_WIDTH_CODE = 0xDC87;
constexpr uint16_t MTP_PROPERTY_HEIGHT_CODE = 0xDC88;
constexpr uint16_t MTP_PROPERTY_DURATION_CODE = 0xDC89;
constexpr uint16_t MTP_PROPERTY_RATING_CODE = 0xDC8A;
constexpr uint16_t MTP_PROPERTY_TRACK_CODE = 0xDC8B;
constexpr uint16_t MTP_PROPERTY_GENRE_CODE = 0xDC8C;
constexpr uint16_t MTP_PROPERTY_CREDITS_CODE = 0xDC8D;
constexpr uint16_t MTP_PROPERTY_LYRICS_CODE = 0xDC8E;
constexpr uint16_t MTP_PROPERTY_SUBSCRIPTION_CONTENT_ID_CODE = 0xDC8F;
constexpr uint16_t MTP_PROPERTY_PRODUCED_BY_CODE = 0xDC90;
constexpr uint16_t MTP_PROPERTY_USE_COUNT_CODE = 0xDC91;
constexpr uint16_t MTP_PROPERTY_SKIP_COUNT_CODE = 0xDC92;
constexpr uint16_t MTP_PROPERTY_LAST_ACCESSED_CODE = 0xDC93;
constexpr uint16_t MTP_PROPERTY_PARENTAL_RATING_CODE = 0xDC94;
constexpr uint16_t MTP_PROPERTY_META_GENRE_CODE = 0xDC95;
constexpr uint16_t MTP_PROPERTY_COMPOSER_CODE = 0xDC96;
constexpr uint16_t MTP_PROPERTY_EFFECTIVE_RATING_CODE = 0xDC97;
constexpr uint16_t MTP_PROPERTY_SUBTITLE_CODE = 0xDC98;
constexpr uint16_t MTP_PROPERTY_ORIGINAL_RELEASE_DATE_CODE = 0xDC99;
constexpr uint16_t MTP_PROPERTY_ALBUM_NAME_CODE = 0xDC9A;
constexpr uint16_t MTP_PROPERTY_ALBUM_ARTIST_CODE = 0xDC9B;
constexpr uint16_t MTP_PROPERTY_MOOD_CODE = 0xDC9C;
constexpr uint16_t MTP_PROPERTY_DRM_STATUS_CODE = 0xDC9D;
constexpr uint16_t MTP_PROPERTY_SUB_DESCRIPTION_CODE = 0xDC9E;
constexpr uint16_t MTP_PROPERTY_IS_CROPPED_CODE = 0xDCD1;
constexpr uint16_t MTP_PROPERTY_IS_COLOUR_CORRECTED_CODE = 0xDCD2;
constexpr uint16_t MTP_PROPERTY_IMAGE_BIT_DEPTH_CODE = 0xDCD3;
constexpr uint16_t MTP_PROPERTY_FNUMBER_CODE = 0xDCD4;
constexpr uint16_t MTP_PROPERTY_EXPOSURE_TIME_CODE = 0xDCD5;
constexpr uint16_t MTP_PROPERTY_EXPOSURE_INDEX_CODE = 0xDCD6;
constexpr uint16_t MTP_PROPERTY_TOTAL_BITRATE_CODE = 0xDE91;
constexpr uint16_t MTP_PROPERTY_BITRATE_TYPE_CODE = 0xDE92;
constexpr uint16_t MTP_PROPERTY_SAMPLE_RATE_CODE = 0xDE93;
constexpr uint16_t MTP_PROPERTY_NUMBER_OF_CHANNELS_CODE = 0xDE94;
constexpr uint16_t MTP_PROPERTY_AUDIO_BITDEPTH_CODE = 0xDE95;
constexpr uint16_t MTP_PROPERTY_SCAN_TYPE_CODE = 0xDE97;
constexpr uint16_t MTP_PROPERTY_AUDIO_WAVE_CODEC_CODE = 0xDE99;
constexpr uint16_t MTP_PROPERTY_AUDIO_BITRATE_CODE = 0xDE9A;
constexpr uint16_t MTP_PROPERTY_VIDEO_FOURCC_CODEC_CODE = 0xDE9B;
constexpr uint16_t MTP_PROPERTY_VIDEO_BITRATE_CODE = 0xDE9C;
constexpr uint16_t MTP_PROPERTY_FRAMES_PER_THOUSAND_SECONDS_CODE = 0xDE9D;
constexpr uint16_t MTP_PROPERTY_KEYFRAME_DISTANCE_CODE = 0xDE9E;
constexpr uint16_t MTP_PROPERTY_BUFFER_SIZE_CODE = 0xDE9F;
constexpr uint16_t MTP_PROPERTY_ENCODING_QUALITY_CODE = 0xDEA0;
constexpr uint16_t MTP_PROPERTY_ENCODING_PROFILE_CODE = 0xDEA1;
constexpr uint16_t MTP_PROPERTY_DISPLAY_NAME_CODE = 0xDCE0;
constexpr uint16_t MTP_PROPERTY_BODY_TEXT_CODE = 0xDCE1;
constexpr uint16_t MTP_PROPERTY_SUBJECT_CODE = 0xDCE2;
constexpr uint16_t MTP_PROPERTY_PRIORITY_CODE = 0xDCE3;
constexpr uint16_t MTP_PROPERTY_GIVEN_NAME_CODE = 0xDD00;
constexpr uint16_t MTP_PROPERTY_MIDDLE_NAMES_CODE = 0xDD01;
constexpr uint16_t MTP_PROPERTY_FAMILY_NAME_CODE = 0xDD02;
constexpr uint16_t MTP_PROPERTY_PREFIX_CODE = 0xDD03;
constexpr uint16_t MTP_PROPERTY_SUFFIX_CODE = 0xDD04;
constexpr uint16_t MTP_PROPERTY_PHONETIC_GIVEN_NAME_CODE = 0xDD05;
constexpr uint16_t MTP_PROPERTY_PHONETIC_FAMILY_NAME_CODE = 0xDD06;
constexpr uint16_t MTP_PROPERTY_EMAIL_PRIMARY_CODE = 0xDD07;
constexpr uint16_t MTP_PROPERTY_EMAIL_PERSONAL_1_CODE = 0xDD08;
constexpr uint16_t MTP_PROPERTY_EMAIL_PERSONAL_2_CODE = 0xDD09;
constexpr uint16_t MTP_PROPERTY_EMAIL_BUSINESS_1_CODE = 0xDD0A;
constexpr uint16_t MTP_PROPERTY_EMAIL_BUSINESS_2_CODE = 0xDD0B;
constexpr uint16_t MTP_PROPERTY_EMAIL_OTHERS_CODE = 0xDD0C;
constexpr uint16_t MTP_PROPERTY_PHONE_NUMBER_PRIMARY_CODE = 0xDD0D;
constexpr uint16_t MTP_PROPERTY_PHONE_NUMBER_PERSONAL_CODE = 0xDD0E;
constexpr uint16_t MTP_PROPERTY_PHONE_NUMBER_PERSONAL_2_CODE = 0xDD0F;
constexpr uint16_t MTP_PROPERTY_PHONE_NUMBER_BUSINESS_CODE = 0xDD10;
constexpr uint16_t MTP_PROPERTY_PHONE_NUMBER_BUSINESS_2_CODE = 0xDD11;
constexpr uint16_t MTP_PROPERTY_PHONE_NUMBER_MOBILE_CODE = 0xDD12;
constexpr uint16_t MTP_PROPERTY_PHONE_NUMBER_MOBILE_2_CODE = 0xDD13;
constexpr uint16_t MTP_PROPERTY_FAX_NUMBER_PRIMARY_CODE = 0xDD14;
constexpr uint16_t MTP_PROPERTY_FAX_NUMBER_PERSONAL_CODE = 0xDD15;
constexpr uint16_t MTP_PROPERTY_FAX_NUMBER_BUSINESS_CODE = 0xDD16;
constexpr uint16_t MTP_PROPERTY_PAGER_NUMBER_CODE = 0xDD17;
constexpr uint16_t MTP_PROPERTY_PHONE_NUMBER_OTHERS_CODE = 0xDD18;
constexpr uint16_t MTP_PROPERTY_PRIMARY_WEB_ADDRESS_CODE = 0xDD19;
constexpr uint16_t MTP_PROPERTY_PERSONAL_WEB_ADDRESS_CODE = 0xDD1A;
constexpr uint16_t MTP_PROPERTY_BUSINESS_WEB_ADDRESS_CODE = 0xDD1B;
constexpr uint16_t MTP_PROPERTY_INSTANT_MESSENGER_ADDRESS_CODE = 0xDD1C;
constexpr uint16_t MTP_PROPERTY_INSTANT_MESSENGER_ADDRESS_2_CODE = 0xDD1D;
constexpr uint16_t MTP_PROPERTY_INSTANT_MESSENGER_ADDRESS_3_CODE = 0xDD1E;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_FULL_CODE = 0xDD1F;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_LINE_1_CODE = 0xDD20;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_LINE_2_CODE = 0xDD21;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_CITY_CODE = 0xDD22;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_REGION_CODE = 0xDD23;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_POSTAL_CODE_CODE = 0xDD24;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_COUNTRY_CODE = 0xDD25;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_FULL_CODE = 0xDD26;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_LINE_1_CODE = 0xDD27;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_LINE_2_CODE = 0xDD28;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_CITY_CODE = 0xDD29;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_REGION_CODE = 0xDD2A;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_POSTAL_CODE_CODE = 0xDD2B;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_COUNTRY_CODE = 0xDD2C;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_OTHER_FULL_CODE = 0xDD2D;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_OTHER_LINE_1_CODE = 0xDD2E;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_OTHER_LINE_2_CODE = 0xDD2F;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_OTHER_CITY_CODE = 0xDD30;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_OTHER_REGION_CODE = 0xDD31;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_OTHER_POSTAL_CODE_CODE = 0xDD32;
constexpr uint16_t MTP_PROPERTY_POSTAL_ADDRESS_OTHER_COUNTRY_CODE = 0xDD33;
constexpr uint16_t MTP_PROPERTY_ORGANIZATION_NAME_CODE = 0xDD34;
constexpr uint16_t MTP_PROPERTY_PHONETIC_ORGANIZATION_NAME_CODE = 0xDD35;
constexpr uint16_t MTP_PROPERTY_ROLE_CODE = 0xDD36;
constexpr uint16_t MTP_PROPERTY_BIRTHDATE_CODE = 0xDD37;
constexpr uint16_t MTP_PROPERTY_MESSAGE_TO_CODE = 0xDD40;
constexpr uint16_t MTP_PROPERTY_MESSAGE_CC_CODE = 0xDD41;
constexpr uint16_t MTP_PROPERTY_MESSAGE_BCC_CODE = 0xDD42;
constexpr uint16_t MTP_PROPERTY_MESSAGE_READ_CODE = 0xDD43;
constexpr uint16_t MTP_PROPERTY_MESSAGE_RECEIVED_TIME_CODE = 0xDD44;
constexpr uint16_t MTP_PROPERTY_MESSAGE_SENDER_CODE = 0xDD45;
constexpr uint16_t MTP_PROPERTY_ACTIVITY_BEGIN_TIME_CODE = 0xDD50;
constexpr uint16_t MTP_PROPERTY_ACTIVITY_END_TIME_CODE = 0xDD51;
constexpr uint16_t MTP_PROPERTY_ACTIVITY_LOCATION_CODE = 0xDD52;
constexpr uint16_t MTP_PROPERTY_ACTIVITY_REQUIRED_ATTENDEES_CODE = 0xDD54;
constexpr uint16_t MTP_PROPERTY_ACTIVITY_OPTIONAL_ATTENDEES_CODE = 0xDD55;
constexpr uint16_t MTP_PROPERTY_ACTIVITY_RESOURCES_CODE = 0xDD56;
constexpr uint16_t MTP_PROPERTY_ACTIVITY_ACCEPTED_CODE = 0xDD57;
constexpr uint16_t MTP_PROPERTY_ACTIVITY_TENTATIVE_CODE = 0xDD58;
constexpr uint16_t MTP_PROPERTY_ACTIVITY_DECLINED_CODE = 0xDD59;
constexpr uint16_t MTP_PROPERTY_ACTIVITY_REMINDER_TIME_CODE = 0xDD5A;
constexpr uint16_t MTP_PROPERTY_ACTIVITY_OWNER_CODE = 0xDD5B;
constexpr uint16_t MTP_PROPERTY_ACTIVITY_STATUS_CODE = 0xDD5C;
constexpr uint16_t MTP_PROPERTY_OWNER_CODE = 0xDD5D;
constexpr uint16_t MTP_PROPERTY_EDITOR_CODE = 0xDD5E;
constexpr uint16_t MTP_PROPERTY_WEBMASTER_CODE = 0xDD5F;
constexpr uint16_t MTP_PROPERTY_URL_SOURCE_CODE = 0xDD60;
constexpr uint16_t MTP_PROPERTY_URL_DESTINATION_CODE = 0xDD61;
constexpr uint16_t MTP_PROPERTY_TIME_BOOKMARK_CODE = 0xDD62;
constexpr uint16_t MTP_PROPERTY_OBJECT_BOOKMARK_CODE = 0xDD63;
constexpr uint16_t MTP_PROPERTY_BYTE_BOOKMARK_CODE = 0xDD64;
constexpr uint16_t MTP_PROPERTY_LAST_BUILD_DATE_CODE = 0xDD70;
constexpr uint16_t MTP_PROPERTY_TIME_TO_LIVE_CODE = 0xDD71;
constexpr uint16_t MTP_PROPERTY_MEDIA_GUID_CODE = 0xDD72;

// MTP Event
constexpr int32_t E_SUCCESS = 0;
constexpr int32_t MTP_SEND_ADD = 500000;
constexpr int32_t MTP_SEND_ADD_TIMES = 3;
constexpr uint16_t MTP_EVENT_UNDEFINED_CODE = 0x4000;
constexpr uint16_t MTP_EVENT_CANCEL_TRANSACTION_CODE = 0x4001;
constexpr uint16_t MTP_EVENT_OBJECT_ADDED_CODE = 0x4002;
constexpr uint16_t MTP_EVENT_OBJECT_REMOVED_CODE = 0x4003;
constexpr uint16_t MTP_EVENT_STORE_ADDED_CODE = 0x4004;
constexpr uint16_t MTP_EVENT_STORE_REMOVED_CODE = 0x4005;
constexpr uint16_t MTP_EVENT_DEVICE_PROP_CHANGED_CODE = 0x4006;
constexpr uint16_t MTP_EVENT_OBJECT_INFO_CHANGED_CODE = 0x4007;
constexpr uint16_t MTP_EVENT_DEVICE_INFO_CHANGED_CODE = 0x4008;
constexpr uint16_t MTP_EVENT_REQUEST_OBJECT_TRANSFER_CODE = 0x4009;
constexpr uint16_t MTP_EVENT_STORE_FULL_CODE = 0x400A;
constexpr uint16_t MTP_EVENT_DEVICE_RESET_CODE = 0x400B;
constexpr uint16_t MTP_EVENT_STORAGE_INFO_CHANGED_CODE = 0x400C;
constexpr uint16_t MTP_EVENT_CAPTURE_COMPLETE_CODE = 0x400D;
constexpr uint16_t MTP_EVENT_UNREPORTED_STATUS_CODE = 0x400E;
constexpr uint16_t MTP_EVENT_OBJECT_PROP_CHANGED_CODE = 0xC801;
constexpr uint16_t MTP_EVENT_OBJECT_PROP_DESC_CHANGED_CODE = 0xC802;
constexpr uint16_t MTP_EVENT_OBJECT_REFERENCES_CHANGED_CODE = 0xC803;

// MTP Response
constexpr uint16_t MTP_UNDEFINED_CODE = 0x2000;
constexpr uint16_t MTP_OK_CODE = 0x2001;
constexpr uint16_t MTP_GENERAL_ERROR_CODE = 0x2002;
constexpr uint16_t MTP_SESSION_NOT_OPEN_CODE = 0x2003;
constexpr uint16_t MTP_INVALID_TRANSACTIONID_CODE = 0x2004;
constexpr uint16_t MTP_OPERATION_NOT_SUPPORTED_CODE = 0x2005;
constexpr uint16_t MTP_PARAMETER_NOT_SUPPORTED_CODE = 0x2006;
constexpr uint16_t MTP_INCOMPLETE_TRANSFER_CODE = 0x2007;
constexpr uint16_t MTP_INVALID_STORAGEID_CODE = 0x2008;
constexpr uint16_t MTP_INVALID_OBJECTHANDLE_CODE = 0x2009;
constexpr uint16_t MTP_DEVICEPROP_NOT_SUPPORTED_CODE = 0x200A;
constexpr uint16_t MTP_INVALID_OBJECTFORMATCODE_CODE = 0x200B;
constexpr uint16_t MTP_STORE_FULL_CODE = 0x200C;
constexpr uint16_t MTP_OBJECT_WRITEPROTECTED_CODE = 0x200D;
constexpr uint16_t MTP_STORE_READ_ONLY_CODE = 0x200E;
constexpr uint16_t MTP_ACCESS_DENIED_CODE = 0x200F;
constexpr uint16_t MTP_NO_THUMBNAIL_PRESENT_CODE = 0x2010;
constexpr uint16_t MTP_SELFTEST_FAILED_CODE = 0x2011;
constexpr uint16_t MTP_PARTIAL_DELETION_CODE = 0x2012;
constexpr uint16_t MTP_STORE_NOT_AVAILABLE_CODE = 0x2013;
constexpr uint16_t MTP_SPECIFICATION_BY_FORMAT_UNSUPPORTED_CODE = 0x2014;
constexpr uint16_t MTP_NO_VALID_OBJECTINFO_CODE = 0x2015;
constexpr uint16_t MTP_INVALID_CODE_FORMAT_CODE = 0x2016;
constexpr uint16_t MTP_UNKNOWN_VENDOR_CODE_CODE = 0x2017;
constexpr uint16_t MTP_CAPTURE_ALREADY_TERMINATED_CODE = 0x2018;
constexpr uint16_t MTP_DEVICE_BUSY_CODE = 0x2019;
constexpr uint16_t MTP_INVALID_PARENTOBJECT_CODE = 0x201A;
constexpr uint16_t MTP_INVALID_DEVICEPROP_FORMAT_CODE = 0x201B;
constexpr uint16_t MTP_INVALID_DEVICEPROP_VALUE_CODE = 0x201C;
constexpr uint16_t MTP_INVALID_PARAMETER_CODE = 0x201D;
constexpr uint16_t MTP_SESSION_ALREADY_OPEN_CODE = 0x201E;
constexpr uint16_t MTP_TRANSACTION_CANCELLED_CODE = 0x201F;
constexpr uint16_t MTP_SPECIFICATION_OF_DESTINATION_UNSUPPORTED_CODE = 0x2020;
constexpr uint16_t MTP_INVALID_OBJECTPROPCODE_CODE = 0xA801;
constexpr uint16_t MTP_INVALID_OBJECTPROP_FORMAT_CODE = 0xA802;
constexpr uint16_t MTP_INVALID_OBJECTPROP_VALUE_CODE = 0xA803;
constexpr uint16_t MTP_INVALID_OBJECTREFERENCE_CODE = 0xA804;
constexpr uint16_t MTP_GROUP_NOT_SUPPORTED_CODE = 0xA805;
constexpr uint16_t MTP_INVALID_DATASET_CODE = 0xA806;
constexpr uint16_t MTP_SPECIFICATION_BY_GROUP_UNSUPPORTED_CODE = 0xA807;
constexpr uint16_t MTP_SPECIFICATION_BY_DEPTH_UNSUPPORTED_CODE = 0xA808;
constexpr uint16_t MTP_OBJECT_TOO_LARGE_CODE = 0xA809;
constexpr uint16_t MTP_OBJECTPROP_NOT_SUPPORTED_CODE = 0xA80A;

// MTP Data Types
constexpr int MTP_TYPE_UNDEFINED_CODE = 0x0000;
constexpr int MTP_TYPE_INT8_CODE = 0x0001;
constexpr int MTP_TYPE_UINT8_CODE = 0x0002;
constexpr int MTP_TYPE_INT16_CODE = 0x0003;
constexpr int MTP_TYPE_UINT16_CODE = 0x0004;
constexpr int MTP_TYPE_INT32_CODE = 0x0005;
constexpr int MTP_TYPE_UINT32_CODE = 0x0006;
constexpr int MTP_TYPE_INT64_CODE = 0x0007;
constexpr int MTP_TYPE_UINT64_CODE = 0x0008;
constexpr int MTP_TYPE_INT128_CODE = 0x0009;
constexpr int MTP_TYPE_UINT128_CODE = 0x000A;
constexpr int MTP_TYPE_AINT8_CODE = 0x4001;
constexpr int MTP_TYPE_AUINT8_CODE = 0x4002;
constexpr int MTP_TYPE_AINT16_CODE = 0x4003;
constexpr int MTP_TYPE_AUINT16_CODE = 0x4004;
constexpr int MTP_TYPE_AINT32_CODE = 0x4005;
constexpr int MTP_TYPE_AUINT32_CODE = 0x4006;
constexpr int MTP_TYPE_AINT64_CODE = 0x4007;
constexpr int MTP_TYPE_AUINT64_CODE = 0x4008;
constexpr int MTP_TYPE_AINT128_CODE = 0x4009;
constexpr int MTP_TYPE_AUINT128_CODE = 0x400A;
constexpr int MTP_TYPE_STRING_CODE = 0xFFFF;

// MTP Container Offsets
constexpr int MTP_CONTAINER_LENGTH_OFFSET = 0;
constexpr int MTP_CONTAINER_TYPE_OFFSET = 4;
constexpr int MTP_CONTAINER_CODE_OFFSET = 6;
constexpr int MTP_CONTAINER_TRANSACTION_ID_OFFSET = 8;
constexpr int MTP_CONTAINER_PARAMETER_OFFSET = 12;
constexpr int32_t MTP_CONTAINER_HEADER_SIZE = 12;
constexpr int32_t MTP_PARAMETER_SIZE = 4;

// Association Type
constexpr int MTP_ASSOCIATION_TYPE_UNDEFINED_CODE = 0x0000;
constexpr int MTP_ASSOCIATION_TYPE_GENERIC_FOLDER_CODE = 0x0001;

constexpr int MTP_STORAGE_UNDEFINED = 0x0000;
constexpr int MTP_STORAGE_FIXEDROM = 0x0001;
constexpr int MTP_STORAGE_REMOVABLEROM = 0x0002;
constexpr int MTP_STORAGE_FIXEDRAM = 0x0003;
constexpr int MTP_STORAGE_REMOVABLERAM = 0x0004;
// Filesystem Type
constexpr int MTP_FILESYSTEM_UNDEFINED = 0x0000;
constexpr int MTP_FILESYSTEM_GENERICFLAT = 0x0001;
constexpr int MTP_FILESYSTEM_GENERICHIERARCHICAL = 0x0002;
constexpr int MTP_FILESYSTEM_DCF = 0x0003;
// Access Capability
constexpr int MTP_ACCESS_READ_WRITE = 0x0000;
constexpr int MTP_ACCESS_READ_ONLY_WITHOUT_OBJECT_DELETION = 0x0001;
constexpr int MTP_ACCESS_READ_ONLY_WITH_OBJECT_DELETION = 0x0002;

// storage
constexpr uint32_t MTP_STORAGE_ID_ALL = 0xFFFFFFFF; // all storage
constexpr uint32_t MTP_STORAGE_ID_ALL2 = 0; // all storage

// perceived device type
constexpr uint32_t MTP_PERCEIVED_DEVICE_TYPE_GENERIC = 0x00000000;
constexpr uint32_t MTP_PERCEIVED_DEVICE_TYPE_STILL_IMAGE_VIDEO_CAMERA = 0x00000001;
constexpr uint32_t MTP_PERCEIVED_DEVICE_TYPE_MEDIA_PLAYER = 0x00000002;
constexpr uint32_t MTP_PERCEIVED_DEVICE_TYPE_MOBILE_HANDSET = 0x00000003;
constexpr uint32_t MTP_PERCEIVED_DEVICE_TYPE_VIDEO_PLAYER = 0x00000004;
constexpr uint32_t MTP_PERCEIVED_DEVICE_TYPE_PERSONAL = 0x00000005;
constexpr uint32_t MTP_PERCEIVED_DEVICE_TYPE_AUDIO_RECORDER = 0x00000005;

using int128_t = int32_t[4];
using uint128_t = uint32_t[4];
using UInt8List = std::vector<uint8_t>;
using UInt16List = std::vector<uint16_t>;
using UInt32List = std::vector<uint32_t>;
using UInt64List = std::vector<uint64_t>;
using Int8List = std::vector<int8_t>;
using Int16List = std::vector<int16_t>;
using Int32List = std::vector<int32_t>;
using Int64List = std::vector<int64_t>;

// MTP Data Types
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_UNDEFINED = 0x0000;          // Undefined
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_INT8 = 0x0001;          // Signed 8-bit integer
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_UINT8 = 0x0002;          // Unsigned 8-bit integer
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_INT16 = 0x0003;          // Signed 16-bit integer
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_UINT16 = 0x0004;          // Unsigned 16-bit integer
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_INT32 = 0x0005;          // Signed 32-bit integer
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_UINT32 = 0x0006;          // Unsigned 32-bit integer
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_INT64 = 0x0007;          // Signed 64-bit integer
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_UINT64 = 0x0008;          // Unsigned 64-bit integer
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_INT128 = 0x0009;          // Signed 128-bit integer
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_UINT128 = 0x000A;          // Unsigned 128-bit integer
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_AINT8 = 0x4001;          // Array of signed 8-bit integers
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_AUINT8 = 0x4002;          // Array of unsigned 8-bit integers
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_AINT16 = 0x4003;          // Array of signed 16-bit integers
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_AUINT16 = 0x4004;          // Array of unsigned 16-bit integers
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_AINT32 = 0x4005;          // Array of signed 32-bit integers
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_AUINT32 = 0x4006;          // Array of unsigned 32-bit integers
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_AINT64 = 0x4007;          // Array of signed 64-bit integers
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_AUINT64 = 0x4008;          // Array of unsigned 64-bit integers
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_AINT128 = 0x4009;          // Array of signed 128-bit integers
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_AUINT128 = 0x400A;          // Array of unsigned 128-bit integers
constexpr uint16_t  MTP_DEVICE_PROP_DESC_TYPE_STR = 0xFFFF;          // Variable-length Unicode string

// Form_Flag
constexpr uint8_t MTP_DEVICE_PROP_DESC_Form_FLAG_NONE = 0x00;
constexpr uint8_t MTP_DEVICE_PROP_DESC_Form_FLAG_RANGE = 0x01;
constexpr uint8_t MTP_DEVICE_PROP_DESC_Form_FLAG_ENUMERATION = 0x02;

constexpr int BATTERY_LEVEL_MIN = 0;
constexpr int BATTERY_LEVEL_MAX = 100;
constexpr int BATTERY_LEVEL_STEP = 1;

#endif  // FRAMEWORKS_SERVICES_MEDIA_MTP_INCLUDE_MTP_CONSTANTS_H_
