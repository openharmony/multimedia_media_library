/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
#include "image_type.h"
#define MLOG_TAG "MediaLibraryManager"

#include "media_library_manager.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "accesstoken_kit.h"
#include "album_asset.h"
#include "datashare_abs_result_set.h"
#include "datashare_predicates.h"
#include "fetch_result.h"
#include "file_asset.h"
#include "image_source.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_tracer.h"
#include "medialibrary_type_const.h"
#include "post_proc.h"
#include "permission_utils.h"
#include "result_set_utils.h"
#include "string_ex.h"
#include "thumbnail_const.h"
#include "unique_fd.h"

#ifdef IMAGE_PURGEABLE_PIXELMAP
#include "purgeable_pixelmap_builder.h"
#endif

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
shared_ptr<DataShare::DataShareHelper> MediaLibraryManager::sDataShareHelper_ = nullptr;
constexpr int32_t DEFAULT_THUMBNAIL_SIZE = 256;
constexpr int32_t MAX_DEFAULT_THUMBNAIL_SIZE = 768;

struct UriParams {
    string path;
    string fileUri;
    Size size;
    bool isAstc;
};

MediaLibraryManager *MediaLibraryManager::GetMediaLibraryManager()
{
    static MediaLibraryManager mediaLibMgr;
    return &mediaLibMgr;
}

void MediaLibraryManager::InitMediaLibraryManager(const sptr<IRemoteObject> &token)
{
    token_ = token;
    if (sDataShareHelper_ == nullptr) {
        sDataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    }
}

static void UriAppendKeyValue(string &uri, const string &key, const string &value)
{
    string uriKey = key + '=';
    if (uri.find(uriKey) != string::npos) {
        return;
    }
    char queryMark = (uri.find('?') == string::npos) ? '?' : '&';
    string append = queryMark + key + '=' + value;
    size_t posJ = uri.find('#');
    if (posJ == string::npos) {
        uri += append;
    } else {
        uri.insert(posJ, append);
    }
}

static void GetCreateUri(string &uri)
{
    uri = PAH_CREATE_PHOTO;
    const std::string API_VERSION = "api_version";
    UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
}

static int32_t parseCreateArguments(const string &displayName, DataShareValuesBucket &valuesBucket)
{
    MediaType mediaType = MediaFileUtils::GetMediaType(displayName);
    if (mediaType != MEDIA_TYPE_IMAGE && mediaType != MEDIA_TYPE_VIDEO) {
        MEDIA_ERR_LOG("Failed to create Asset, invalid file type");
        return E_ERR;
    }
    valuesBucket.Put(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, static_cast<int32_t>(mediaType));
    return E_OK;
}

string MediaLibraryManager::CreateAsset(const string &displayName)
{
    if (sDataShareHelper_ == nullptr || displayName.empty()) {
        MEDIA_ERR_LOG("Failed to create Asset, datashareHelper is nullptr");
        sDataShareHelper_ = DataShare::DataShareHelper::Creator(token_, MEDIALIBRARY_DATA_URI);
    }
    DataShareValuesBucket valuesBucket;
    auto ret = parseCreateArguments(displayName, valuesBucket);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to create Asset, parse create argument fails");
        return "";
    }
    string createFileUri;
    GetCreateUri(createFileUri);
    Uri createUri(createFileUri);
    string outUri;
    int index = sDataShareHelper_->InsertExt(createUri, valuesBucket, outUri);
    if (index < 0) {
        MEDIA_ERR_LOG("Failed to create Asset, insert database error!");
        return "";
    }
    return outUri;
}

static bool CheckUri(string &uri)
{
    if (uri.find("..") != string::npos) {
        return false;
    }
    string uriprex = "file://media";
    return uri.substr(0, uriprex.size()) == uriprex;
}

int32_t MediaLibraryManager::OpenAsset(string &uri, const string openMode)
{
    if (openMode.empty()) {
        return E_ERR;
    }
    if (!CheckUri(uri)) {
        MEDIA_ERR_LOG("invalid uri");
        return E_ERR;
    }
    string originOpenMode = openMode;
    std::transform(originOpenMode.begin(), originOpenMode.end(),
        originOpenMode.begin(), [](unsigned char c) {return std::tolower(c);});
    if (!MEDIA_OPEN_MODES.count(originOpenMode)) {
        return E_ERR;
    }
    if (sDataShareHelper_ == nullptr) {
        MEDIA_ERR_LOG("Failed to open Asset, datashareHelper is nullptr");
        return E_ERR;
    }
    Uri openUri(uri);
    return sDataShareHelper_->OpenFile(openUri, openMode);
}

int32_t MediaLibraryManager::CloseAsset(const string &uri, const int32_t fd)
{
    int32_t retVal = E_FAIL;
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_URI, uri);

    if (sDataShareHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri closeAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CLOSEASSET);

        if (close(fd) == E_SUCCESS) {
            retVal = sDataShareHelper_->Insert(closeAssetUri, valuesBucket);
        }

        if (retVal == E_FAIL) {
            MEDIA_ERR_LOG("Failed to close the file");
        }
    }

    return retVal;
}

int32_t MediaLibraryManager::QueryTotalSize(MediaVolume &outMediaVolume)
{
    auto dataShareHelper = DataShare::DataShareHelper::Creator(token_, MEDIALIBRARY_DATA_URI);
    if (dataShareHelper == nullptr) {
        MEDIA_ERR_LOG("dataShareHelper is null");
        return E_FAIL;
    }
    vector<string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_QUERYOPRN_QUERYVOLUME + "/" + MEDIA_QUERYOPRN_QUERYVOLUME);
    DataSharePredicates predicates;
    auto queryResultSet = dataShareHelper->Query(uri, predicates, columns);
    if (queryResultSet == nullptr) {
        MEDIA_ERR_LOG("queryResultSet is null!");
        return E_FAIL;
    }
    auto count = 0;
    auto ret = queryResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("get rdbstore failed");
        return E_HAS_DB_ERROR;
    }
    MEDIA_INFO_LOG("count = %{public}d", (int)count);
    if (count >= 0) {
        while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
            int mediatype = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_MEDIA_TYPE,
                queryResultSet, TYPE_INT32));
            int64_t size = get<int64_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_SIZE,
                queryResultSet, TYPE_INT64));
            outMediaVolume.SetSize(mediatype, size);
        }
    }
    MEDIA_INFO_LOG("Size:Files:%{public}" PRId64 " Videos:%{public}" PRId64 " Images:%{public} " PRId64
        " Audio:%{public}" PRId64,
        outMediaVolume.GetFilesSize(), outMediaVolume.GetVideosSize(),
        outMediaVolume.GetImagesSize(), outMediaVolume.GetAudiosSize());
    return E_SUCCESS;
}

std::shared_ptr<DataShareResultSet> MediaLibraryManager::GetResultSetFromDb(string columnName, const string &value,
    vector<string> &columns)
{
    Uri uri(MEDIALIBRARY_MEDIA_PREFIX);
    DataSharePredicates predicates;
    predicates.EqualTo(columnName, value);
    predicates.And()->EqualTo(MEDIA_DATA_DB_IS_TRASH, to_string(NOT_TRASHED));
    DatashareBusinessError businessError;

    if (sDataShareHelper_ == nullptr) {
        MEDIA_ERR_LOG("sDataShareHelper_ is null");
        return nullptr;
    }
    return sDataShareHelper_->Query(uri, predicates, columns, &businessError);
}

static int32_t SolvePath(const string &filePath, string &tempPath, string &userId)
{
    if (filePath.empty()) {
        return E_INVALID_PATH;
    }

    string prePath = PRE_PATH_VALUES;
    if (filePath.find(prePath) != 0) {
        return E_CHECK_ROOT_DIR_FAIL;
    }
    string postpath = filePath.substr(prePath.length());
    auto pos = postpath.find('/');
    if (pos == string::npos) {
        return E_INVALID_ARGUMENTS;
    }
    userId = postpath.substr(0, pos);
    postpath = postpath.substr(pos + 1);
    tempPath = prePath + postpath;

    return E_SUCCESS;
}

static int32_t CheckResultSet(std::shared_ptr<DataShareResultSet> &resultSet)
{
    int count = 0;
    auto ret = resultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to get resultset row count, ret: %{public}d", ret);
        return ret;
    }
    if (count <= 0) {
        MEDIA_ERR_LOG("Failed to get count, count: %{public}d", count);
        return E_FAIL;
    }
    ret = resultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to go to first row, ret: %{public}d", ret);
        return ret;
    }
    return E_SUCCESS;
}


int32_t MediaLibraryManager::GetFilePathFromUri(const Uri &fileUri, string &filePath, string userId)
{
    string uri = fileUri.ToString();
    MediaFileUri virtualUri(uri);
    if (!virtualUri.IsValid()) {
        return E_URI_INVALID;
    }
    string virtualId = virtualUri.GetFileId();
#ifdef MEDIALIBRARY_COMPATIBILITY
    if (MediaFileUtils::GetTableFromVirtualUri(uri) != MEDIALIBRARY_TABLE) {
        MEDIA_INFO_LOG("uri:%{private}s does not match Files Table", uri.c_str());
        return E_URI_INVALID;
    }
#endif
    vector<string> columns = { MEDIA_DATA_DB_FILE_PATH };
    auto resultSet = MediaLibraryManager::GetResultSetFromDb(MEDIA_DATA_DB_ID, virtualId, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_INVALID_URI,
        "GetFilePathFromUri::uri is not correct: %{private}s", uri.c_str());
    if (CheckResultSet(resultSet) != E_SUCCESS) {
        return E_FAIL;
    }

    std::string tempPath = ResultSetUtils::GetStringValFromColumn(1, resultSet);
    if (tempPath.find(ROOT_MEDIA_DIR) != 0) {
        return E_CHECK_ROOT_DIR_FAIL;
    }
    string relativePath = tempPath.substr((ROOT_MEDIA_DIR + DOCS_PATH).length());
    auto pos = relativePath.find('/');
    if (pos == string::npos) {
        return E_INVALID_ARGUMENTS;
    }
    relativePath = relativePath.substr(0, pos + 1);
    if ((relativePath != DOC_DIR_VALUES) && (relativePath != DOWNLOAD_DIR_VALUES)) {
        return E_DIR_CHECK_DIR_FAIL;
    }

    string prePath = PRE_PATH_VALUES;
    string postpath = tempPath.substr(prePath.length());
    tempPath = prePath + userId + "/" + postpath;
    filePath = tempPath;
    return E_SUCCESS;
}

int32_t MediaLibraryManager::GetUriFromFilePath(const string &filePath, Uri &fileUri, string &userId)
{
    if (filePath.empty()) {
        return E_INVALID_PATH;
    }

    string tempPath;
    SolvePath(filePath, tempPath, userId);
    if (tempPath.find(ROOT_MEDIA_DIR) != 0) {
        return E_CHECK_ROOT_DIR_FAIL;
    }
    string relativePath = tempPath.substr((ROOT_MEDIA_DIR + DOCS_PATH).length());
    auto pos = relativePath.find('/');
    if (pos == string::npos) {
        return E_INVALID_ARGUMENTS;
    }
    relativePath = relativePath.substr(0, pos + 1);
    if ((relativePath != DOC_DIR_VALUES) && (relativePath != DOWNLOAD_DIR_VALUES)) {
        return E_DIR_CHECK_DIR_FAIL;
    }

    vector<string> columns = { MEDIA_DATA_DB_ID};
    auto resultSet = MediaLibraryManager::GetResultSetFromDb(MEDIA_DATA_DB_FILE_PATH, tempPath, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_INVALID_URI,
        "GetUriFromFilePath::tempPath is not correct: %{private}s", tempPath.c_str());
    if (CheckResultSet(resultSet) != E_SUCCESS) {
        return E_FAIL;
    }

    int32_t fileId = ResultSetUtils::GetIntValFromColumn(0, resultSet);
#ifdef MEDIALIBRARY_COMPATIBILITY
    int64_t virtualId = MediaFileUtils::GetVirtualIdByType(fileId, MediaType::MEDIA_TYPE_FILE);
    fileUri = MediaFileUri(MediaType::MEDIA_TYPE_FILE, to_string(virtualId), "", MEDIA_API_VERSION_V9);
#else
    fileUri = MediaFileUri(MediaType::MEDIA_TYPE_FILE, to_string(fileId), "", MEDIA_API_VERSION_V9);
#endif
    return E_SUCCESS;
}

static inline bool IsSmallThumb(const int32_t width, const int32_t height)
{
    if (((width == DEFAULT_MTH_SIZE) && (height == DEFAULT_MTH_SIZE)) ||
        ((width == DEFAULT_YEAR_SIZE) && (height == DEFAULT_YEAR_SIZE))) {
        return true;
    }
    return false;
}

static std::string GetSandboxPath(const std::string &path, const Size &size, bool isAudio, bool isAstc)
{
    if (path.length() < ROOT_MEDIA_DIR.length()) {
        return "";
    }
    int min = std::min(size.width, size.height);
    int max = std::max(size.width, size.height);
    std::string suffixStr = path.substr(ROOT_MEDIA_DIR.length()) + "/";
    if (isAudio) {
        if (min == DEFAULT_ORIGINAL && max == DEFAULT_ORIGINAL) {
            suffixStr += "LCD.jpg";
        } else if (min <= DEFAULT_THUMBNAIL_SIZE && max <= MAX_DEFAULT_THUMBNAIL_SIZE) {
            suffixStr += "THM.jpg";
        } else {
            suffixStr += "LCD.jpg";
        }
    } else {
        if (size.width == DEFAULT_MTH_SIZE && size.height == DEFAULT_MTH_SIZE) {
            suffixStr += "MTH.jpg";
        } else if (size.width == DEFAULT_YEAR_SIZE && size.height == DEFAULT_YEAR_SIZE) {
            suffixStr += "YEAR.jpg";
        } else if (size.width == DEFAULT_ORIGINAL && size.height == DEFAULT_ORIGINAL) {
            suffixStr += "LCD.jpg";
        } else if (min <= DEFAULT_THUMBNAIL_SIZE && max <= MAX_DEFAULT_THUMBNAIL_SIZE) {
            suffixStr += isAstc ? "THM_ASTC.astc" : "THM.jpg";
        } else {
            suffixStr += "LCD.jpg";
        }
    }

    return ROOT_SANDBOX_DIR + ".thumbs/" + suffixStr;
}

int MediaLibraryManager::OpenThumbnail(string &uriStr, const string &path, const Size &size, bool isAstc)
{
    if (sDataShareHelper_ == nullptr) {
        MEDIA_ERR_LOG("Failed to open thumbnail, datashareHelper is nullptr");
        return E_ERR;
    }
    if (!path.empty()) {
        string sandboxPath = GetSandboxPath(path, size,
            (MediaFileUri::GetMediaTypeFromUri(uriStr) == MediaType::MEDIA_TYPE_AUDIO), isAstc);
        int fd = -1;
        if (!sandboxPath.empty()) {
            fd = open(sandboxPath.c_str(), O_RDONLY);
        }
        if (fd > 0) {
            return fd;
        }
        if (IsAsciiString(path)) {
            uriStr += "&" + THUMBNAIL_PATH + "=" + path;
        }
    }
    Uri openUri(uriStr);
    return sDataShareHelper_->OpenFile(openUri, "R");
}

/**
 * Get the file uri prefix with id
 * eg. Input: file://media/Photo/10/IMG_xxx/01.jpg
 *     Output: file://media/Photo/10
 */
static void GetUriIdPrefix(std::string &fileUri)
{
    MediaFileUri mediaUri(fileUri);
    if (!mediaUri.IsApi10()) {
        return;
    }
    auto slashIdx = fileUri.rfind('/');
    if (slashIdx == std::string::npos) {
        return;
    }
    auto tmpUri = fileUri.substr(0, slashIdx);
    slashIdx = tmpUri.rfind('/');
    if (slashIdx == std::string::npos) {
        return;
    }
    fileUri = tmpUri.substr(0, slashIdx);
}

static bool GetParamsFromUri(const string &uri, const bool isOldVer, UriParams &uriParams)
{
    MediaFileUri mediaUri(uri);
    if (!mediaUri.IsValid()) {
        return false;
    }
    if (isOldVer) {
        auto index = uri.find("thumbnail");
        if (index == string::npos) {
            return false;
        }
        uriParams.fileUri = uri.substr(0, index - 1);
        GetUriIdPrefix(uriParams.fileUri);
        index += strlen("thumbnail");
        index = uri.find('/', index);
        if (index == string::npos) {
            return false;
        }
        index += 1;
        auto tmpIdx = uri.find('/', index);
        if (tmpIdx == string::npos) {
            return false;
        }

        int32_t width = 0;
        StrToInt(uri.substr(index, tmpIdx - index), width);
        int32_t height = 0;
        StrToInt(uri.substr(tmpIdx + 1), height);
        uriParams.size = { .width = width, .height = height };
    } else {
        auto qIdx = uri.find('?');
        if (qIdx == string::npos) {
            return false;
        }
        uriParams.fileUri = uri.substr(0, qIdx);
        GetUriIdPrefix(uriParams.fileUri);
        auto &queryKey = mediaUri.GetQueryKeys();
        if (queryKey.count(THUMBNAIL_PATH) != 0) {
            uriParams.path = queryKey[THUMBNAIL_PATH];
        }
        if (queryKey.count(THUMBNAIL_WIDTH) != 0) {
            uriParams.size.width = stoi(queryKey[THUMBNAIL_WIDTH]);
        }
        if (queryKey.count(THUMBNAIL_HEIGHT) != 0) {
            uriParams.size.height = stoi(queryKey[THUMBNAIL_HEIGHT]);
        }
        if (queryKey.count(THUMBNAIL_OPER) != 0) {
            uriParams.isAstc = queryKey[THUMBNAIL_HEIGHT] == MEDIA_DATA_DB_THUMB_ASTC;
        }
    }
    return true;
}

static bool IfSizeEqualsRatio(const Size &imageSize, const Size &targetSize)
{
    if (imageSize.height <= 0 || targetSize.height <= 0) {
        return false;
    }

    float imageSizeScale = static_cast<float>(imageSize.width) / static_cast<float>(imageSize.height);
    float targetSizeScale = static_cast<float>(targetSize.width) / static_cast<float>(targetSize.height);
    if (imageSizeScale - targetSizeScale > FLOAT_EPSILON || targetSizeScale - imageSizeScale > FLOAT_EPSILON) {
        return false;
    } else {
        return true;
    }
}

unique_ptr<PixelMap> MediaLibraryManager::DecodeThumbnail(UniqueFd& uniqueFd, const Size& size)
{
    MediaLibraryTracer tracer;
    tracer.Start("ImageSource::CreateImageSource");
    SourceOptions opts;
    uint32_t err = 0;
    unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(uniqueFd.Get(), opts, err);
    if (imageSource  == nullptr) {
        MEDIA_ERR_LOG("CreateImageSource err %{public}d", err);
        return nullptr;
    }

    ImageInfo imageInfo;
    err = imageSource->GetImageInfo(0, imageInfo);
    if (err != E_OK) {
        MEDIA_ERR_LOG("GetImageInfo err %{public}d", err);
        return nullptr;
    }

    bool isEqualsRatio = IfSizeEqualsRatio(imageInfo.size, size);
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize = isEqualsRatio ? size : imageInfo.size;
    decodeOpts.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, err);
    if (pixelMap == nullptr) {
        MEDIA_ERR_LOG("CreatePixelMap err %{public}d", err);
        return nullptr;
    }
#ifdef IMAGE_PURGEABLE_PIXELMAP
    PurgeableBuilder::MakePixelMapToBePurgeable(pixelMap, uniqueFd.Get(), opts, decodeOpts);
#endif
    PostProc postProc;
    if (size.width != DEFAULT_ORIGINAL && !isEqualsRatio && !postProc.CenterScale(size, *pixelMap)) {
        return nullptr;
    }
    return pixelMap;
}

unique_ptr<PixelMap> MediaLibraryManager::GetPixelMapWithoutDecode(UniqueFd &uniqueFd, const Size &size)
{
    Media::InitializationOptions option = {
        .size = size,
        .pixelFormat = PixelFormat::RGB_565
    };
    unique_ptr<PixelMap> pixel = Media::PixelMap::Create(option);
    if (pixel == nullptr) {
        MEDIA_ERR_LOG("Can not create pixel");
        return nullptr;
    }

    struct stat statInfo;
    if (fstat(uniqueFd.Get(), &statInfo) == E_ERR) {
        return nullptr;
    }
    uint8_t *buffer = static_cast<uint8_t*>(malloc(statInfo.st_size));
    if (buffer == nullptr) {
        return nullptr;
    }
    read(uniqueFd.Get(), buffer, statInfo.st_size);
    pixel->SetPixelsAddr(buffer, nullptr, statInfo.st_size, AllocatorType::HEAP_ALLOC, nullptr);
    return pixel;
}

unique_ptr<PixelMap> MediaLibraryManager::QueryThumbnail(const std::string &uri, Size &size,
                                                         const string &path, bool isAstc)
{
    MediaLibraryTracer tracer;
    tracer.Start("QueryThumbnail uri:" + uri);

    string oper = isAstc ? MEDIA_DATA_DB_THUMB_ASTC : MEDIA_DATA_DB_THUMBNAIL;
    string openUriStr = uri + "?" + MEDIA_OPERN_KEYWORD + "=" + oper + "&" + MEDIA_DATA_DB_WIDTH +
        "=" + to_string(size.width) + "&" + MEDIA_DATA_DB_HEIGHT + "=" + to_string(size.height);
    tracer.Start("DataShare::OpenThumbnail");
    UniqueFd uniqueFd(MediaLibraryManager::OpenThumbnail(openUriStr, path, size, isAstc));
    if (uniqueFd.Get() < 0) {
        MEDIA_ERR_LOG("queryThumb is null, errCode is %{public}d", uniqueFd.Get());
        return nullptr;
    }
    tracer.Finish();
    if (IsSmallThumb(size.width, size.height) &&
        (MediaFileUri::GetMediaTypeFromUri(uri) != MediaType::MEDIA_TYPE_AUDIO)) {
        // only get MTH and YEAR thumbnails
        return GetPixelMapWithoutDecode(uniqueFd, size);
    } else {
        return DecodeThumbnail(uniqueFd, size);
    }
}

std::unique_ptr<PixelMap> MediaLibraryManager::GetThumbnail(const Uri &uri)
{
    // uri is dataability:///media/image/<id>/thumbnail/<width>/<height>
    string uriStr = uri.ToString();
    auto thumbLatIdx = uriStr.find("thumbnail");
    if (thumbLatIdx == string::npos || thumbLatIdx > uriStr.length()) {
        return nullptr;
    }
    thumbLatIdx += strlen("thumbnail");
    bool isOldVersion = uriStr[thumbLatIdx] == '/';
    UriParams uriParams;
    if (!GetParamsFromUri(uriStr, isOldVersion, uriParams)) {
        return nullptr;
    }
    auto pixelmap = QueryThumbnail(uriParams.fileUri, uriParams.size, uriParams.path, uriParams.isAstc);
    return pixelmap;
}
} // namespace Media
} // namespace OHOS
