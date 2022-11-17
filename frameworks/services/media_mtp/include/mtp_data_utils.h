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
#ifndef FRAMEWORKS_SERVICES_MEDIA_MTP_INCLUDE_MTP_DATA_UTILS_H_
#define FRAMEWORKS_SERVICES_MEDIA_MTP_INCLUDE_MTP_DATA_UTILS_H_
#include <memory>
#include <vector>
#include <string>
#include <variant>
#include <sys/time.h>
#include <stdio.h>

#include "datashare_result_set.h"
#include "mtp_operation_context.h"
#include "property.h"
#include "userfile_manager_types.h"
#include "result_set_utils.h"

namespace OHOS {
namespace Media {
struct PropertyValue {
    uint64_t outIntVal = 0;
    uint128_t outLongVal = {0};
    std::string outStrVal;
};
const std::string MTP_FORMAT_ALL = ".all"; // Undefined
const std::string MTP_FORMAT_UNDEFINED = ".undefined"; // Undefined
const std::string MTP_FORMAT_ASSOCIATION = ".floader"; // associations (folders and directories)
const std::string MTP_FORMAT_SCRIPT = ".js"; // script files
const std::string MTP_FORMAT_EXECUTABLE = ".exe"; // executable files
const std::string MTP_FORMAT_TEXT = ".txt"; // text files
const std::string MTP_FORMAT_HTML = ".html"; // HTML files
const std::string MTP_FORMAT_DPOF = ".dp"; // DPOF files
const std::string MTP_FORMAT_AIFF = ".aiff"; // AIFF audio files
const std::string MTP_FORMAT_WAV = ".wav"; // WAV audio files
const std::string MTP_FORMAT_MP3 = ".mp3"; // MP3 audio files
const std::string MTP_FORMAT_AVI = ".avi"; // AVI video files
const std::string MTP_FORMAT_MPEG = ".mpeg"; // MPEG video files
const std::string MTP_FORMAT_ASF = ".asf"; // ASF files
// Unknown image files which are not specified in PTP specification
const std::string MTP_FORMAT_DEFINED = ".image"; // Unknown image files
const std::string MTP_FORMAT_EXIF_JPEG = ".jpeg?.jpg"; // JPEG image files
const std::string MTP_FORMAT_TIFF_EP = ".tiff"; // TIFF EP image files
const std::string MTP_FORMAT_FLASHPIX = ".swf";
const std::string MTP_FORMAT_BMP = ".bmp"; // BMP image files
const std::string MTP_FORMAT_CIFF = ".ciff";
const std::string MTP_FORMAT_GIF = ".giff"; // GIF image files
const std::string MTP_FORMAT_JFIF = ".jsif"; // JFIF image files
const std::string MTP_FORMAT_CD = ".cd";
const std::string MTP_FORMAT_PICT = ".pict"; // PICT image files
const std::string MTP_FORMAT_PNG = ".png"; // PNG image files
const std::string MTP_FORMAT_TIFF = ".tif"; // TIFF image files
const std::string MTP_FORMAT_TIFF_IT = ".tiff";
const std::string MTP_FORMAT_JP2 = ".jp2"; // JP2 files
const std::string MTP_FORMAT_JPX = ".jpx"; // JPX files
const std::string MTP_FORMAT_UNDEFINED_FIRMWARE = ".undefinedfirmware"; // firmware files
const std::string MTP_FORMAT_WINDOWS_IMAGE_FORMAT = ".img"; // Windows image files
const std::string MTP_FORMAT_UNDEFINED_AUDIO = ".undefinedaudio"; // undefined audio files files
const std::string MTP_FORMAT_WMA = ".wma"; // WMA audio files
const std::string MTP_FORMAT_OGG = ".ogg"; // OGG audio files
const std::string MTP_FORMAT_AAC = ".aac"; // AAC audio files
const std::string MTP_FORMAT_AUDIBLE = ".aa"; // Audible audio files
const std::string MTP_FORMAT_FLAC = ".flac"; // FLAC audio files
const std::string MTP_FORMAT_UNDEFINED_VIDEO = ".undefinedvideo"; // undefined video files
const std::string MTP_FORMAT_WMV = ".wmv"; // WMV video files
const std::string MTP_FORMAT_MP4_CONTAINER = ".mp4"; // MP4 files
const std::string MTP_FORMAT_MP2 = ".mp2"; // MP2 files
const std::string MTP_FORMAT_3GP_CONTAINER = ".3gp"; // 3GP files

const std::string MTP_FORMAT_UNDEFINED_COLLECTION = ".undefinedcollections"; // undefined collections
const std::string MTP_FORMAT_ABSTRACT_MULTIMEDIA_ALBUM = ".album"; // multimedia albums
const std::string MTP_FORMAT_ABSTRACT_IMAGE_ALBUM = ".albumimage"; // image albums
const std::string MTP_FORMAT_ABSTRACT_AUDIO_ALBUM = ".albumaudio"; // audio albums
const std::string MTP_FORMAT_ABSTRACT_VIDEO_ALBUM = ".albumvideo"; // video albums
const std::string MTP_FORMAT_ABSTRACT_AUDIO_VIDEO_PLAYLIST = ""; // abstract AV playlists
const std::string MTP_FORMAT_ABSTRACT_CONTACT_GROUP = "";
const std::string MTP_FORMAT_ABSTRACT_MESSAGE_FOLDER = ".mesfloader";
const std::string MTP_FORMAT_ABSTRACT_CHAPTERED_PRODUCTION = "";
const std::string MTP_FORMAT_ABSTRACT_AUDIO_PLAYLIST = ".allaudio"; // abstract audio playlists
const std::string MTP_FORMAT_ABSTRACT_VIDEO_PLAYLIST = ".allvideo"; // abstract video playlists
const std::string MTP_FORMAT_ABSTRACT_MEDIACAST = ""; // abstract mediacasts
const std::string MTP_FORMAT_WPL_PLAYLIST = ".wpl"; // WPL playlist files
const std::string MTP_FORMAT_M3U_PLAYLIST = ".m3u"; // M3u playlist files
const std::string MTP_FORMAT_MPL_PLAYLIST = ".mpl"; // MPL playlist files
const std::string MTP_FORMAT_ASX_PLAYLIST = ".asx"; // ASX playlist files
const std::string MTP_FORMAT_PLS_PLAYLIST = ".pls"; // PLS playlist files
const std::string MTP_FORMAT_UNDEFINED_DOCUMENT = ".undefineddocument"; // undefined document files
const std::string MTP_FORMAT_ABSTRACT_DOCUMENT = ".alldocuments"; // abstract documents
const std::string MTP_FORMAT_XML_DOCUMENT = ".xml"; // XML documents
const std::string MTP_FORMAT_MICROSOFT_WORD_DOCUMENT = ".doc"; // MS Word documents
const std::string MTP_FORMAT_MHT_COMPILED_HTML_DOCUMENT = ".html";
const std::string MTP_FORMAT_MICROSOFT_EXCEL_SPREADSHEET = ""; // MS Excel spreadsheets
const std::string MTP_FORMAT_MICROSOFT_POWERPOINT_PRESENTATION = ""; // MS PowerPoint presentatiosn
const std::string MTP_FORMAT_UNDEFINED_MESSAGE = "";
const std::string MTP_FORMAT_ABSTRACT_MESSAGE = "";
const std::string MTP_FORMAT_UNDEFINED_CONTACT = "";
const std::string MTP_FORMAT_ABSTRACT_CONTACT = "";
const std::string MTP_FORMAT_VCARD_2 = "";

class MtpDataUtils {
public:
    static int32_t SolveHandlesFormatData(const uint16_t format, std::string &outExtension, MediaType &outMediaType);
    static int32_t SolveSendObjectFormatData(const uint16_t format, MediaType &outMediaType);
    static int32_t SolveSetObjectPropValueData(const std::shared_ptr<MtpOperationContext> &context,
        std::string &outColName, std::variant<int64_t, std::string> &outColVal);
    static void GetMediaTypeByformat(const uint16_t format, MediaType &outMediaType);
    static void GetPropGropByMediaType(const MediaType &mediaType, std::vector<std::string> &outPropGrop);
    static int32_t GetPropListBySet(const uint32_t property,
        const uint16_t format, const std::shared_ptr<DataShare::DataShareResultSet> &resultSet,
        std::shared_ptr<std::vector<Property>> &outProps);
    static int32_t GetPropValueBySet(const uint32_t property,
        const std::shared_ptr<DataShare::DataShareResultSet> &resultSet,
        PropertyValue &outPropValue);
    static int32_t GetMediaTypeByName(std::string &displayName, MediaType &outMediaType);
private:
    static int32_t GetPropList(const std::shared_ptr<DataShare::DataShareResultSet> &resultSet,
        const std::shared_ptr<UInt16List> &properties, std::shared_ptr<std::vector<Property>> &outProps);
    static void GetFormatByPath(const std::string &path, uint16_t &outFormat);
    static std::variant<int32_t, int64_t, std::string> ReturnError(const std::string &errMsg,
        const ResultSetDataType &type);
    static int32_t GetFormat(const std::shared_ptr<DataShare::DataShareResultSet> &resultSet, uint16_t &outFormat);
    static void GetOneRowPropList(uint32_t handle, const std::shared_ptr<DataShare::DataShareResultSet> &resultSet,
        const std::shared_ptr<UInt16List> &properties, std::shared_ptr<std::vector<Property>> &outProps);
    static void GetOneRowPropVal(const std::shared_ptr<DataShare::DataShareResultSet> &resultSet,
        const uint32_t property, PropertyValue &outPropValue);
    static void SetOneDefaultlPropList(uint32_t handle,
        uint16_t property, std::shared_ptr<std::vector<Property>> &outProps);
    static void SetProperty(const std::string &column,
        const std::shared_ptr<DataShare::DataShareResultSet> &resultSet, ResultSetDataType &type, Property &prop);
};
} // namespace Media
} // namespace OHOS
#endif  // FRAMEWORKS_SERVICES_MEDIA_MTP_INCLUDE_MTP_DATA_UTILS_H_
