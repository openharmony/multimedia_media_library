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
#include <map>
#include "medialibrary_errno.h"
#include "medialibrary_db_const.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_mtp_utils.h"
#include "mtp_data_utils.h"
#include "mtp_constants.h"
#include "mtp_packet_tools.h"
#include "payload_data/get_object_props_supported_data.h"
#include "payload_data.h"
#include "rdb_errno.h"

using namespace std;
namespace OHOS {
namespace Media {
struct NormalProperty {
    int32_t intValue;
    string strValue;
};
static constexpr int32_t INTTYPE16 = 16;
static constexpr int32_t INTTYPE128 = 128;
static constexpr int32_t STRINGTYPE = -1;
static const string MEDIA_DATA_DB_FORMAT = "format";

static const map<uint16_t, string> FormatMap = {
    { 0, MTP_FORMAT_ALL},
    { MTP_FORMAT_UNDEFINED_CODE, MTP_FORMAT_UNDEFINED },
    { MTP_FORMAT_ASSOCIATION_CODE, MTP_FORMAT_ASSOCIATION },
    { MTP_FORMAT_SCRIPT_CODE, MTP_FORMAT_SCRIPT },
    { MTP_FORMAT_EXECUTABLE_CODE, MTP_FORMAT_EXECUTABLE },
    { MTP_FORMAT_TEXT_CODE, MTP_FORMAT_TEXT },
    { MTP_FORMAT_DPOF_CODE, MTP_FORMAT_DPOF },
    { MTP_FORMAT_AIFF_CODE, MTP_FORMAT_AIFF },
    { MTP_FORMAT_WAV_CODE, MTP_FORMAT_WAV },
    { MTP_FORMAT_HTML_CODE, MTP_FORMAT_HTML },
    { MTP_FORMAT_MP3_CODE, MTP_FORMAT_MP3 },
    { MTP_FORMAT_AVI_CODE, MTP_FORMAT_AVI },
    { MTP_FORMAT_MPEG_CODE, MTP_FORMAT_ASF },
    // image files...
    { MTP_FORMAT_DEFINED_CODE, MTP_FORMAT_DEFINED },
    { MTP_FORMAT_EXIF_JPEG_CODE, MTP_FORMAT_EXIF_JPEG },
    { MTP_FORMAT_FLASHPIX_CODE, MTP_FORMAT_FLASHPIX },
    { MTP_FORMAT_BMP_CODE, MTP_FORMAT_BMP },
    { MTP_FORMAT_CIFF_CODE, MTP_FORMAT_CIFF },
    { MTP_FORMAT_GIF_CODE, MTP_FORMAT_GIF },
    { MTP_FORMAT_JFIF_CODE, MTP_FORMAT_JFIF },
    { MTP_FORMAT_CD_CODE, MTP_FORMAT_CD },
    { MTP_FORMAT_PICT_CODE, MTP_FORMAT_PICT },
    { MTP_FORMAT_PNG_CODE, MTP_FORMAT_PNG },
    { MTP_FORMAT_TIFF_CODE, MTP_FORMAT_TIFF },
    { MTP_FORMAT_JP2_CODE, MTP_FORMAT_JP2 },
    { MTP_FORMAT_JPX_CODE, MTP_FORMAT_JPX },
    // firmware files
    { MTP_FORMAT_UNDEFINED_FIRMWARE_CODE, MTP_FORMAT_UNDEFINED_FIRMWARE },
    // Windows image files
    { MTP_FORMAT_WINDOWS_IMAGE_FORMAT_CODE, MTP_FORMAT_WINDOWS_IMAGE_FORMAT },
    // audio files
    { MTP_FORMAT_UNDEFINED_AUDIO_CODE, MTP_FORMAT_UNDEFINED_AUDIO },
    { MTP_FORMAT_WMA_CODE, MTP_FORMAT_WMA },
    { MTP_FORMAT_OGG_CODE, MTP_FORMAT_OGG },
    { MTP_FORMAT_AAC_CODE, MTP_FORMAT_AAC },
    { MTP_FORMAT_AUDIBLE_CODE, MTP_FORMAT_AUDIBLE },
    { MTP_FORMAT_FLAC_CODE, MTP_FORMAT_FLAC },
    // video files
    { MTP_FORMAT_UNDEFINED_VIDEO_CODE, MTP_FORMAT_UNDEFINED_VIDEO },
    { MTP_FORMAT_WMV_CODE, MTP_FORMAT_WMV },
    { MTP_FORMAT_MP4_CONTAINER_CODE, MTP_FORMAT_MP4_CONTAINER },
    { MTP_FORMAT_MP2_CODE, MTP_FORMAT_MP2 },
    { MTP_FORMAT_3GP_CONTAINER_CODE, MTP_FORMAT_3GP_CONTAINER },
    // unknown
    { MTP_FORMAT_UNDEFINED_COLLECTION_CODE, MTP_FORMAT_UNDEFINED_COLLECTION },
    { MTP_FORMAT_ABSTRACT_MULTIMEDIA_ALBUM_CODE, MTP_FORMAT_ABSTRACT_MULTIMEDIA_ALBUM },
    { MTP_FORMAT_ABSTRACT_IMAGE_ALBUM_CODE, MTP_FORMAT_ABSTRACT_IMAGE_ALBUM },
    { MTP_FORMAT_ABSTRACT_AUDIO_ALBUM_CODE, MTP_FORMAT_ABSTRACT_AUDIO_ALBUM },
    { MTP_FORMAT_ABSTRACT_VIDEO_ALBUM_CODE, MTP_FORMAT_ABSTRACT_VIDEO_ALBUM },
    { MTP_FORMAT_ABSTRACT_AUDIO_VIDEO_PLAYLIST_CODE, MTP_FORMAT_ABSTRACT_AUDIO_VIDEO_PLAYLIST },
    { MTP_FORMAT_ABSTRACT_CONTACT_GROUP_CODE, MTP_FORMAT_ABSTRACT_CONTACT_GROUP },
    { MTP_FORMAT_ABSTRACT_MESSAGE_FOLDER_CODE, MTP_FORMAT_ABSTRACT_MESSAGE_FOLDER },
    { MTP_FORMAT_ABSTRACT_CHAPTERED_PRODUCTION_CODE, MTP_FORMAT_ABSTRACT_CHAPTERED_PRODUCTION },
    { MTP_FORMAT_ABSTRACT_AUDIO_PLAYLIST_CODE, MTP_FORMAT_ABSTRACT_AUDIO_PLAYLIST },
    { MTP_FORMAT_ABSTRACT_VIDEO_PLAYLIST_CODE, MTP_FORMAT_ABSTRACT_VIDEO_PLAYLIST },
    { MTP_FORMAT_ABSTRACT_MEDIACAST_CODE, MTP_FORMAT_ABSTRACT_MEDIACAST },
    { MTP_FORMAT_WPL_PLAYLIST_CODE, MTP_FORMAT_WPL_PLAYLIST },
    { MTP_FORMAT_M3U_PLAYLIST_CODE, MTP_FORMAT_M3U_PLAYLIST },
    { MTP_FORMAT_MPL_PLAYLIST_CODE, MTP_FORMAT_MPL_PLAYLIST },
    { MTP_FORMAT_ASX_PLAYLIST_CODE, MTP_FORMAT_ASX_PLAYLIST },
    { MTP_FORMAT_PLS_PLAYLIST_CODE, MTP_FORMAT_PLS_PLAYLIST },
    { MTP_FORMAT_UNDEFINED_DOCUMENT_CODE, MTP_FORMAT_UNDEFINED_DOCUMENT },
    { MTP_FORMAT_XML_DOCUMENT_CODE, MTP_FORMAT_XML_DOCUMENT },
    { MTP_FORMAT_ABSTRACT_DOCUMENT_CODE, MTP_FORMAT_ABSTRACT_DOCUMENT },
    { MTP_FORMAT_MICROSOFT_WORD_DOCUMENT_CODE, MTP_FORMAT_MICROSOFT_WORD_DOCUMENT },
    { MTP_FORMAT_MHT_COMPILED_HTML_DOCUMENT_CODE, MTP_FORMAT_MHT_COMPILED_HTML_DOCUMENT },
    { MTP_FORMAT_MICROSOFT_EXCEL_SPREADSHEET_CODE, MTP_FORMAT_MICROSOFT_EXCEL_SPREADSHEET },
    { MTP_FORMAT_UNDEFINED_MESSAGE_CODE, MTP_FORMAT_UNDEFINED_MESSAGE },
    { MTP_FORMAT_ABSTRACT_MESSAGE_CODE, MTP_FORMAT_ABSTRACT_MESSAGE },
    { MTP_FORMAT_UNDEFINED_CONTACT_CODE, MTP_FORMAT_UNDEFINED_CONTACT },
    { MTP_FORMAT_ABSTRACT_CONTACT_CODE, MTP_FORMAT_ABSTRACT_CONTACT },
    { MTP_FORMAT_MICROSOFT_POWERPOINT_PRESENTATION_CODE, MTP_FORMAT_MICROSOFT_POWERPOINT_PRESENTATION },
    { MTP_FORMAT_VCARD_2_CODE, MTP_FORMAT_VCARD_2 }
};

static const map<std::string, MediaType> FormatAllMap = {
    { MTP_FORMAT_ALL, MEDIA_TYPE_ALL },
    { MTP_FORMAT_ABSTRACT_AUDIO_PLAYLIST, MEDIA_TYPE_AUDIO },
    { MTP_FORMAT_ABSTRACT_VIDEO_PLAYLIST, MEDIA_TYPE_VIDEO },
    { MTP_FORMAT_ABSTRACT_VIDEO_PLAYLIST, MEDIA_TYPE_VIDEO },
    { MTP_FORMAT_ASSOCIATION, MEDIA_TYPE_ALBUM }
};

static const map<uint16_t, MediaType> FormatMediaTypeMap = {
    { 0, MEDIA_TYPE_ALL },
    { MTP_FORMAT_UNDEFINED_CODE, MEDIA_TYPE_FILE },
    { MTP_FORMAT_DEFINED_CODE, MEDIA_TYPE_IMAGE },
    { MTP_FORMAT_EXIF_JPEG_CODE, MEDIA_TYPE_IMAGE },
    { MTP_FORMAT_FLASHPIX_CODE, MEDIA_TYPE_IMAGE },
    { MTP_FORMAT_BMP_CODE, MEDIA_TYPE_IMAGE },
    { MTP_FORMAT_CIFF_CODE, MEDIA_TYPE_IMAGE },
    { MTP_FORMAT_GIF_CODE, MEDIA_TYPE_IMAGE },
    { MTP_FORMAT_JFIF_CODE, MEDIA_TYPE_IMAGE },
    { MTP_FORMAT_CD_CODE, MEDIA_TYPE_IMAGE },
    { MTP_FORMAT_PICT_CODE, MEDIA_TYPE_IMAGE },
    { MTP_FORMAT_PNG_CODE, MEDIA_TYPE_IMAGE },
    { MTP_FORMAT_TIFF_CODE, MEDIA_TYPE_IMAGE },
    { MTP_FORMAT_JP2_CODE, MEDIA_TYPE_IMAGE },
    { MTP_FORMAT_JPX_CODE, MEDIA_TYPE_IMAGE },
    { MTP_FORMAT_UNDEFINED_AUDIO_CODE, MEDIA_TYPE_AUDIO },
    { MTP_FORMAT_WMA_CODE, MEDIA_TYPE_AUDIO },
    { MTP_FORMAT_OGG_CODE, MEDIA_TYPE_AUDIO },
    { MTP_FORMAT_AAC_CODE, MEDIA_TYPE_AUDIO },
    { MTP_FORMAT_AUDIBLE_CODE, MEDIA_TYPE_AUDIO },
    { MTP_FORMAT_FLAC_CODE, MEDIA_TYPE_AUDIO },
    { MTP_FORMAT_UNDEFINED_VIDEO_CODE, MEDIA_TYPE_VIDEO },
    { MTP_FORMAT_WMV_CODE, MEDIA_TYPE_VIDEO },
    { MTP_FORMAT_MP4_CONTAINER_CODE, MEDIA_TYPE_VIDEO },
    { MTP_FORMAT_MP3_CODE, MEDIA_TYPE_AUDIO },
    { MTP_FORMAT_MP2_CODE, MEDIA_TYPE_VIDEO },
    { MTP_FORMAT_3GP_CONTAINER_CODE, MEDIA_TYPE_VIDEO },
    { MTP_FORMAT_ASSOCIATION_CODE, MEDIA_TYPE_ALBUM}
};

static const map<uint32_t, std::string> ObjMediaPropMap = {
    { MTP_PROPERTY_OBJECT_FILE_NAME_CODE, MEDIA_DATA_DB_NAME },
    { MTP_PROPERTY_PARENT_OBJECT_CODE, MEDIA_DATA_DB_PARENT_ID }
};

static const map<uint16_t, int> ObjMediaPropTypeMap = {
    { MTP_PROPERTY_OBJECT_FILE_NAME_CODE, MTP_TYPE_STRING_CODE },
    { MTP_PROPERTY_PARENT_OBJECT_CODE, MTP_TYPE_UINT32_CODE }
};

static const map<std::string, uint16_t> ColumnToPropTypeMap = {
    { MEDIA_DATA_DB_SIZE, MTP_PROPERTY_OBJECT_SIZE_CODE },
    { MEDIA_DATA_DB_NAME, MTP_PROPERTY_OBJECT_FILE_NAME_CODE },
    { MEDIA_DATA_DB_DATE_MODIFIED, MTP_PROPERTY_DATE_MODIFIED_CODE },
    { MEDIA_DATA_DB_PARENT_ID, MTP_PROPERTY_PARENT_OBJECT_CODE },
    { MEDIA_DATA_DB_NAME, MTP_PROPERTY_NAME_CODE },
    { MEDIA_DATA_DB_NAME, MTP_PROPERTY_DISPLAY_NAME_CODE },
    { MEDIA_DATA_DB_DATE_ADDED, MTP_PROPERTY_DATE_ADDED_CODE },
    { MEDIA_DATA_DB_ARTIST, MTP_PROPERTY_ARTIST_CODE },
    { MEDIA_DATA_DB_DURATION, MTP_PROPERTY_DURATION_CODE },
    { MEDIA_DATA_DB_DESCRIPTION, MTP_PROPERTY_DESCRIPTION_CODE },
};

static const map<std::string, ResultSetDataType> ColumnTypeMap = {
    { MEDIA_DATA_DB_ID, TYPE_INT32 },
    { MEDIA_DATA_DB_SIZE, TYPE_INT64 },
    { MEDIA_DATA_DB_PARENT_ID, TYPE_INT32 },
    { MEDIA_DATA_DB_DATE_MODIFIED, TYPE_INT64 },
    { MEDIA_DATA_DB_DATE_ADDED, TYPE_INT64 },
    { MEDIA_DATA_DB_NAME, TYPE_STRING },
    { MEDIA_DATA_DB_DESCRIPTION, TYPE_STRING },
    { MEDIA_DATA_DB_DURATION, TYPE_INT32 },
    { MEDIA_DATA_DB_ARTIST, TYPE_STRING },
    { MEDIA_DATA_DB_AUDIO_ALBUM, TYPE_STRING },
    { MEDIA_DATA_DB_FORMAT, TYPE_INT32 },
};

static const map<uint16_t, std::string> PropColumnMap = {
    { MTP_PROPERTY_OBJECT_FORMAT_CODE, MEDIA_DATA_DB_FORMAT },
    { MTP_PROPERTY_OBJECT_SIZE_CODE, MEDIA_DATA_DB_SIZE },
    { MTP_PROPERTY_OBJECT_FILE_NAME_CODE, MEDIA_DATA_DB_NAME },
    { MTP_PROPERTY_DATE_MODIFIED_CODE, MEDIA_DATA_DB_DATE_MODIFIED },
    { MTP_PROPERTY_PARENT_OBJECT_CODE, MEDIA_DATA_DB_PARENT_ID },
    { MTP_PROPERTY_NAME_CODE, MEDIA_DATA_DB_NAME },
    { MTP_PROPERTY_DISPLAY_NAME_CODE, MEDIA_DATA_DB_NAME },
    { MTP_PROPERTY_DATE_ADDED_CODE, MEDIA_DATA_DB_DATE_ADDED },
    { MTP_PROPERTY_ARTIST_CODE, MEDIA_DATA_DB_ARTIST },
    { MTP_PROPERTY_DURATION_CODE, MEDIA_DATA_DB_DURATION },
};

static const map<uint16_t, int32_t> PropDefaultMap = {
    { MTP_PROPERTY_STORAGE_ID_CODE, DEFAULT_STORAGE_ID },
    { MTP_PROPERTY_PROTECTION_STATUS_CODE, INTTYPE16 },
    { MTP_PROPERTY_PERSISTENT_UID_CODE, INTTYPE128 },
    { MTP_PROPERTY_ALBUM_NAME_CODE, STRINGTYPE },
    { MTP_PROPERTY_ALBUM_ARTIST_CODE, STRINGTYPE },
    { MTP_PROPERTY_TRACK_CODE, INTTYPE16 },
    { MTP_PROPERTY_ORIGINAL_RELEASE_DATE_CODE, STRINGTYPE },
    { MTP_PROPERTY_GENRE_CODE, STRINGTYPE },
};

int32_t MtpDataUtils::SolveHandlesFormatData(const uint16_t format, std::string &outExtension, MediaType &outMediaType)
{
    if (FormatMap.find(format) == FormatMap.end()) {
        MEDIA_ERR_LOG("Can not find format");
        return MTP_ERROR_INVALID_OBJECTHANDLE;
    }
    outExtension = FormatMap.at(format);
    if (FormatAllMap.find(outExtension) != FormatAllMap.end()) {
        outMediaType = FormatAllMap.at(outExtension);
        return MTP_SUCCESS;
    }
    outMediaType = MEDIA_TYPE_DEFAULT;
    return MTP_SUCCESS;
}

int32_t MtpDataUtils::SolveSendObjectFormatData(const uint16_t format, MediaType &outMediaType)
{
    if (FormatMediaTypeMap.find(format) == FormatMediaTypeMap.end()) {
        MEDIA_ERR_LOG("Can not find format");
        outMediaType = MEDIA_TYPE_FILE;
    } else {
        outMediaType = FormatMediaTypeMap.at(format);
    }
    return MTP_SUCCESS;
}

int32_t MtpDataUtils::SolveSetObjectPropValueData(const shared_ptr<MtpOperationContext> &context,
    std::string &outColName, variant<int64_t, std::string> &outColVal)
{
    if (ObjMediaPropTypeMap.find(context->property) == ObjMediaPropTypeMap.end()) {
        MEDIA_ERR_LOG("Can not support propertyType");
        return MTP_ERROR_INVALID_OBJECTPROP_VALUE;
    }
    if (ObjMediaPropMap.find(context->property) == ObjMediaPropMap.end()) {
        MEDIA_ERR_LOG("Can not support this property");
        return MTP_ERROR_INVALID_OBJECTPROP_VALUE;
    } else {
        outColName = ObjMediaPropMap.at(context->property);
    }
    if (context->properType == MTP_TYPE_STRING_CODE) {
        outColVal = context->properStrValue;
        MEDIA_INFO_LOG("context->properStrValue = %{public}s", context->properStrValue.c_str());
    } else {
        outColVal = context->properIntValue;
    }
    return MTP_SUCCESS;
}

void MtpDataUtils::GetMediaTypeByformat(const uint16_t format, MediaType &outMediaType)
{
    if (FormatMediaTypeMap.find(format) == FormatMediaTypeMap.end()) {
        MEDIA_ERR_LOG("Can not find format");
        outMediaType = MEDIA_TYPE_DEFAULT;
    }
    if (FormatMediaTypeMap.find(format) != FormatMediaTypeMap.end()) {
        outMediaType = FormatMediaTypeMap.at(format);
    }
}

int32_t MtpDataUtils::GetPropListBySet(const uint32_t property, const uint16_t format,
    const shared_ptr<DataShare::DataShareResultSet> &resultSet, shared_ptr<vector<Property>> &outProps)
{
    shared_ptr<UInt16List> properties = make_shared<UInt16List>();
    if (property == MTP_PROPERTY_ALL_CODE) {
        shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
        context->format = format;
        shared_ptr<GetObjectPropsSupportedData> payLoadData = make_shared<GetObjectPropsSupportedData>(context);
        payLoadData->GetObjectProps(*properties);
    } else {
        properties->push_back(property);
    }
    return GetPropList(resultSet, properties, outProps);
}

int32_t MtpDataUtils::GetPropList(const shared_ptr<DataShare::DataShareResultSet> &resultSet,
    const shared_ptr<UInt16List> &properties, shared_ptr<vector<Property>> &outProps)
{
    int count = 0;
    resultSet->GetRowCount(count);
    if (properties->size() == 0) {
        return MTP_INVALID_OBJECTPROPCODE_CODE;
    }
    ResultSetDataType idType = TYPE_INT32;
    int32_t handle = 0;
    for (int32_t row = 0; row < count; row++) {
        resultSet->GoToRow(row);
        handle = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_ID, resultSet, idType));
        MEDIA_INFO_LOG("GetPropList %{public}d",
            get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_ID, resultSet, idType)));
        GetOneRowPropList(static_cast<uint32_t>(handle), resultSet, properties, outProps);
    }
    return MTP_SUCCESS;
}

variant<int32_t, int64_t, std::string> MtpDataUtils::ReturnError(const std::string &errMsg,
    const ResultSetDataType &type)
{
    MEDIA_ERR_LOG("%{public}s", errMsg.c_str());
    if ((type) == TYPE_STRING) {
        return "";
    } else {
        return 0;
    }
}

void MtpDataUtils::GetFormatByPath(const std::string &path, uint16_t &outFormat)
{
    if (path.empty()) {
        MEDIA_ERR_LOG("path is nullptr");
        return;
    }
    if (MediaFileUtils::IsDirectory(path)) {
        MEDIA_ERR_LOG("path is dir");
        outFormat = MTP_FORMAT_ASSOCIATION_CODE;
        return;
    }
    size_t slashIndex = path.rfind('/');
    std::string displayName;
    if (slashIndex != std::string::npos) {
        displayName = path.substr(slashIndex + 1);
    }
    size_t extensionIndex = displayName.find(".");
    std::string extension;
    if (extensionIndex != std::string::npos) {
        extension = displayName.substr(extensionIndex);
    } else {
        MEDIA_ERR_LOG("get extensionIndex failed");
        outFormat = MTP_FORMAT_UNDEFINED_CODE;
        return;
    }
    for (auto pair : FormatMap) {
        if ((pair.second).find(extension) != std::string::npos) {
            outFormat = pair.first;
            break;
        }
    }
}

int32_t MtpDataUtils::GetFormat(const shared_ptr<DataShare::DataShareResultSet> &resultSet,
    uint16_t &outFormat)
{
    int index;
    int status;
    int mediaType;
    status = resultSet->GetColumnIndex(MEDIA_DATA_DB_MEDIA_TYPE, index);
    if (status != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("GetColumnIndex failed");
        return E_FAIL;
    }
    resultSet->GetInt(index, mediaType);
    if (mediaType == MEDIA_TYPE_ALBUM) {
        outFormat = MTP_FORMAT_ASSOCIATION_CODE;
        return E_SUCCESS;
    }
    status = resultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, index);
    if (status != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("GetColumnIndex failed");
        return E_FAIL;
    }
    std::string pathVal;
    status = resultSet->GetString(index, pathVal);
    if (status != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("GetString failed");
        return E_FAIL;
    }
    if (pathVal.empty()) {
        MEDIA_ERR_LOG("path is empty");
        return E_FAIL;
    }
    GetFormatByPath(pathVal, outFormat);
    return E_SUCCESS;
}

void LocalTime(struct tm &t, time_t curTime)
{
    time_t curTimeTemp = curTime;
    if (curTimeTemp == 0) {
        curTimeTemp = time(nullptr);
    }
    auto tm = localtime(&curTimeTemp);
    if (tm) {
        t = *tm;
    }
}

std::string Strftime(const std::string &format, time_t curTime)
{
    if (format.empty()) {
        return format;
    }
    struct tm t = {};
    LocalTime(t, curTime);
    char szDTime[32] = "";
    (void)strftime(szDTime, sizeof(szDTime), format.c_str(), &t);
    return szDTime;
}

void MtpDataUtils::SetProperty(const std::string &column, const shared_ptr<DataShare::DataShareResultSet> &resultSet,
    ResultSetDataType &type, Property &prop)
{
    variant<int32_t, std::string, int64_t, double> columnValue =
        ResultSetUtils::GetValFromColumn(column, resultSet, type);
    switch (type) {
        case TYPE_STRING:
            prop.currentValue->str_ = make_shared<std::string>(get<std::string>(columnValue));
            break;
        case TYPE_INT32:
            prop.currentValue->bin_.i32 = get<int32_t>(columnValue);
            break;
        case TYPE_INT64:
            if (column.compare(MEDIA_DATA_DB_DATE_MODIFIED) == 0) {
                prop.currentValue->str_ =
                    make_shared<std::string>(MtpPacketTool::FormatDateTime(get<int64_t>(columnValue)));
            } else {
                prop.currentValue->bin_.i64 = get<int64_t>(columnValue);
            }
            break;
        default:
            break;
    }
}

void MtpDataUtils::GetOneRowPropList(uint32_t handle, const shared_ptr<DataShare::DataShareResultSet> &resultSet,
    const shared_ptr<UInt16List> &properties, shared_ptr<vector<Property>> &outProps)
{
    std::string column;
    ResultSetDataType type;
    for (uint16_t property : *properties) {
        if (PropColumnMap.find(property) != PropColumnMap.end()) {
            auto properType = MtpPacketTool::GetObjectPropTypeByPropCode(property);
            Property prop(property, properType);
            prop.handle_ = handle;
            column = PropColumnMap.at(property);
            type = ColumnTypeMap.at(column);
            if (column.compare(MEDIA_DATA_DB_FORMAT) == 0) {
                uint16_t format = MTP_FORMAT_UNDEFINED_CODE;
                GetFormat(resultSet, format);
                prop.currentValue->bin_.ui16 = format;
                MEDIA_INFO_LOG("prop.currentValue->bin_.ui16 %{public}u", format);
            } else {
                SetProperty(column, resultSet, type, prop);
            }
            outProps->push_back(prop);
        } else if (PropDefaultMap.find(property) != PropDefaultMap.end()) {
            SetOneDefaultlPropList(handle, property, outProps);
        }
    }
}

int32_t MtpDataUtils::GetPropValueBySet(const uint32_t property,
    const shared_ptr<DataShare::DataShareResultSet> &resultSet, PropertyValue &outPropValue)
{
    if (resultSet->GoToFirstRow() != 0) {
        return MTP_ERROR_INVALID_OBJECTHANDLE;
    }
    if (PropColumnMap.find(property) != PropColumnMap.end()) {
        std::string column = PropColumnMap.at(property);
        ResultSetDataType type = ColumnTypeMap.at(column);
        variant<int32_t, std::string, int64_t, double> columnValue =
            ResultSetUtils::GetValFromColumn(column, resultSet, type);
        switch (type) {
            case TYPE_STRING:
                outPropValue.outStrVal = get<std::string>(columnValue);
                break;
            case TYPE_INT32:
                outPropValue.outIntVal = static_cast<uint64_t>(get<int32_t>(columnValue));
                break;
            case TYPE_INT64:
                if (column.compare(MEDIA_DATA_DB_DATE_MODIFIED) == 0) {
                    std::string timeFormat = "%Y-%m-%d %H:%M:%S";
                    outPropValue.outStrVal = Strftime(timeFormat, get<int64_t>(columnValue));
                } else {
                    outPropValue.outIntVal = static_cast<uint64_t>(get<int64_t>(columnValue));
                }
                break;
            default:
                break;
        }
    }
    return MTP_SUCCESS;
}

void MtpDataUtils::SetOneDefaultlPropList(uint32_t handle, uint16_t property, shared_ptr<vector<Property>> &outProps)
{
    auto propType = PropDefaultMap.at(property);
    auto properType = MtpPacketTool::GetObjectPropTypeByPropCode(property);
    Property prop(property, properType);
    prop.handle_ = handle;
    switch (propType) {
        case INTTYPE16:
            prop.currentValue->bin_.i16 = 0;
            break;
        case INTTYPE128:
            prop.currentValue->bin_.i128[OFFSET_0] = static_cast<int32_t>(handle);
            prop.currentValue->bin_.i128[OFFSET_1] = 0;
            prop.currentValue->bin_.i128[OFFSET_2] = 0;
            prop.currentValue->bin_.i128[OFFSET_3] = 0;
            break;
        case STRINGTYPE:
            prop.currentValue->str_ = make_shared<string>("");
            break;
        default:
            prop.currentValue->bin_.i32 = DEFAULT_STORAGE_ID;
            break;
    }
    outProps->push_back(prop);
}

int32_t MtpDataUtils::GetMediaTypeByName(std::string &displayName, MediaType &outMediaType)
{
    size_t displayNameIndex = displayName.find(".");
    std::string extension;
    if (displayNameIndex != std::string::npos) {
        extension = displayName.substr(displayNameIndex);
    } else {
        MEDIA_ERR_LOG("is dir displayName");
        outMediaType = MEDIA_TYPE_ALBUM;
        return E_SUCCESS;
    }
    uint16_t format;
    for (auto pair : FormatMap) {
        if ((pair.second).find(extension) != std::string::npos) {
            format = pair.first;
            break;
        } else {
            format = MTP_FORMAT_UNDEFINED_CODE;
        }
    }
    GetMediaTypeByformat(format, outMediaType);
    return E_SUCCESS;
}

} // namespace Media
} // namespace OHOS
