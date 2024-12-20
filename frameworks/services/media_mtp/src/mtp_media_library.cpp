/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MtpMediaLibrary"

#include "mtp_media_library.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <fstream>
#include <shared_mutex>
#include "mtp_data_utils.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "mtp_error_utils.h"
#include "mtp_packet_tools.h"
#include "mtp_storage_manager.h"
#include "image_packer.h"
#include "avmetadatahelper.h"

namespace OHOS {
namespace Media {
namespace {
using ReadLock = std::shared_lock<std::shared_mutex>;
using WriteLock = std::lock_guard<std::shared_mutex>;
const std::string PUBLIC_REAL_PATH_PRE               = "/storage/media/";
const std::string PUBLIC_REAL_PATH_END               = "/local/files/Docs";
const std::string PUBLIC_DOC                         = "/storage/media/local/files/Docs";
const std::string SD_DOC                             = "/storage/External";
const std::string TRASH_DIR_NAME                     = "/storage/media/local/files/Docs/.Trash";
const std::string RECENT_DIR_NAME                    = "/storage/media/local/files/Docs/.Recent";
const std::string THUMBS_DIR_NAME                    = "/storage/media/local/files/Docs/.thumbs";
const std::string BACKUP_DIR_NAME                    = "/storage/media/local/files/Docs/.backup";
const std::string APPDATA_DIR_NAME                   = "/storage/media/local/files/Docs/appdata";
const std::string DESKTOP_NAME                       = "/storage/media/local/files/Docs/Desktop";
const std::string PATH_SEPARATOR                     = "/";
constexpr uint32_t BASE_USER_RANGE                   = 200000;
constexpr int32_t NORMAL_WIDTH                       = 256;
constexpr int32_t NORMAL_HEIGHT                      = 256;
constexpr int32_t COMPRE_SIZE_LEVEL_2                = 204800;
const std::string THUMBNAIL_FORMAT                   = "image/jpeg";
static constexpr uint8_t THUMBNAIL_MID               = 90;
static std::unordered_map<uint32_t, std::string> handleToPathMap;
static std::unordered_map<std::string, uint32_t> pathToHandleMap;
static std::shared_mutex g_mutex;
enum HANDLE_DEFAULT_ID : uint32_t {
    DEFAULT_PARENT_ID = 0,
    START_ID
};

static std::unordered_map<uint32_t, std::string> storageIdToPathMap;
enum STORAGE_ID : uint32_t {
    INNER_STORAGE_ID = 1,
    SD_START_ID = INNER_STORAGE_ID + 1,
    SD_END_ID = SD_START_ID + 127
};
} // namespace

std::atomic<uint32_t> MtpMediaLibrary::id_ = 0;
std::shared_ptr<MtpMediaLibrary> MtpMediaLibrary::instance_ = nullptr;

std::shared_ptr<MtpMediaLibrary> MtpMediaLibrary::GetInstance()
{
    static std::once_flag oc;
    std::call_once(oc, []() {
        instance_ = std::make_shared<MtpMediaLibrary>();
        if (instance_ != nullptr) {
            instance_->Init();
        }
    });
    return instance_;
}

void MtpMediaLibrary::Init()
{
    id_ = START_ID;
    {
        WriteLock lock(g_mutex);
        handleToPathMap.clear();
        pathToHandleMap.clear();
        storageIdToPathMap.clear();
        std::unordered_map<uint32_t, std::string>().swap(handleToPathMap);
        std::unordered_map<std::string, uint32_t>().swap(pathToHandleMap);
        std::unordered_map<uint32_t, std::string>().swap(storageIdToPathMap);
    }
    // clear all storages, otherwise it maybe has duty data.
    auto manager = MtpStorageManager::GetInstance();
    if (manager != nullptr) {
        manager->ClearStorages();
    }
}

void MtpMediaLibrary::Clear()
{
    MEDIA_INFO_LOG("MtpMediaLibrary::Clear is called");
    Init();
}

uint32_t MtpMediaLibrary::GetId()
{
    return id_++;
}

static bool IsHiddenDirectory(const std::string &dir)
{
    CHECK_AND_RETURN_RET_LOG(!dir.empty(), false, "dir is empty");
    static const std::unordered_map<std::string, uint8_t> hiddenDirs = {
        {TRASH_DIR_NAME, 0},
        {RECENT_DIR_NAME, 0},
        {THUMBS_DIR_NAME, 0},
        {BACKUP_DIR_NAME, 0},
        {APPDATA_DIR_NAME, 0},
        {DESKTOP_NAME, 0}
    };
    if (hiddenDirs.find(dir) == hiddenDirs.end()) {
        return false;
    }
    return true;
}

int32_t MtpMediaLibrary::ScanDirNoDepth(const std::string &root, std::shared_ptr<UInt32List> &out)
{
    CHECK_AND_RETURN_RET_LOG(out != nullptr, E_ERR, "out is nullptr");
    CHECK_AND_RETURN_RET_LOG(access(root.c_str(), R_OK) == 0, E_ERR, "access failed root[%{public}s]", root.c_str());
    if (!sf::exists(root) || !sf::is_directory(root)) {
        MEDIA_ERR_LOG("MtpMediaLibrary::ScanDirNoDepth root[%{public}s] is not exists", root.c_str());
        return E_ERR;
    }
    std::error_code ec;
    for (const auto& entry : sf::directory_iterator(root, ec)) {
        if (ec.value() != MTP_SUCCESS) {
            continue;
        }
        // show not recycle dir
        if (sf::is_directory(entry.path(), ec) && IsHiddenDirectory(entry.path().string())) {
            continue;
        }
        uint32_t id = AddPathToMap(entry.path().string());
        out->push_back(id);
    }
    return MTP_SUCCESS;
}

void MtpMediaLibrary::AddToHandlePathMap(const std::string &path, const uint32_t id)
{
    if (handleToPathMap.find(id) != handleToPathMap.end()) {
        handleToPathMap.erase(id);
    }
    if (pathToHandleMap.find(path) != pathToHandleMap.end()) {
        pathToHandleMap.erase(path);
    }
    pathToHandleMap.emplace(path, id);
    handleToPathMap.emplace(id, path);
}

void MtpMediaLibrary::ModifyHandlePathMap(const std::string &from, const std::string &to)
{
    auto it = pathToHandleMap.find(from);
    if (it == pathToHandleMap.end()) {
        MEDIA_ERR_LOG("MtpMediaLibrary::ModifyHandlePathMap from not found");
        return;
    }
    uint32_t id = it->second;
    pathToHandleMap.erase(it);
    pathToHandleMap.emplace(to, id);

    auto iter = handleToPathMap.find(id);
    if (iter != handleToPathMap.end()) {
        handleToPathMap.erase(iter);
        handleToPathMap.emplace(id, to);
    }
}

void MtpMediaLibrary::ModifyPathHandleMap(const std::string &path, const uint32_t id)
{
    auto it = pathToHandleMap.find(path);
    if (it == pathToHandleMap.end()) {
        MEDIA_ERR_LOG("MtpMediaLibrary::ModifyPathHandleMap from not found");
        return;
    }

    uint32_t originalId = it->second;
    pathToHandleMap.erase(it);
    pathToHandleMap.emplace(path, id);

    auto iter = handleToPathMap.find(originalId);
    if (iter != handleToPathMap.end()) {
        handleToPathMap.erase(iter);
        handleToPathMap.emplace(id, path);
    }
}

bool MtpMediaLibrary::StartsWith(const std::string& str, const std::string& prefix)
{
    if (prefix.size() > str.size() || prefix.empty() || str.empty()) {
        MEDIA_ERR_LOG("MtpMediaLibrary::StartsWith prefix size error");
        return false;
    }

    for (size_t i = 0; i < prefix.size(); ++i) {
        if (str[i] != prefix[i]) {
            return false;
        }
    }
    return true;
}

void MtpMediaLibrary::DeleteHandlePathMap(const std::string &path, const uint32_t id)
{
    WriteLock lock(g_mutex);
    if (pathToHandleMap.find(path) != pathToHandleMap.end()) {
        pathToHandleMap.erase(path);
    }
    if (handleToPathMap.find(id) != handleToPathMap.end()) {
        handleToPathMap.erase(id);
    }
}

int MtpMediaLibrary::ObserverAddPathToMap(const std::string &path)
{
    MEDIA_DEBUG_LOG("MtpMediaLibrary::ObserverAddPathToMap path[%{public}s]", path.c_str());
    {
        WriteLock lock(g_mutex);
        return AddPathToMap(path);
    }
}

void MtpMediaLibrary::ObserverDeletePathToMap(const std::string &path)
{
    MEDIA_DEBUG_LOG("MtpMediaLibrary::ObserverDeletePathToMap path[%{public}s]", path.c_str());
    uint32_t id;
    if (GetIdByPath(path, id) != MTP_SUCCESS) {
        return;
    }
    {
        WriteLock lock(g_mutex);
        ErasePathInfo(id, path);
    }
}

void MtpMediaLibrary::MoveHandlePathMap(const std::string &from, const std::string &to)
{
    std::string prefix = from + "/";
    for (auto it = pathToHandleMap.begin(); it != pathToHandleMap.end();) {
        if (StartsWith(it->first, prefix)) {
            uint32_t eachId = it->second;
            std::string eachStr = it->first;
            it = pathToHandleMap.erase(it);

            std::string eachSuffixString = eachStr.substr(prefix.size());
            std::string newPath = to + "/" + eachSuffixString;
            pathToHandleMap.emplace(newPath, eachId);

            auto iter = handleToPathMap.find(eachId);
            if (iter != handleToPathMap.end()) {
                handleToPathMap.erase(iter);
                handleToPathMap.emplace(eachId, newPath);
            }
        } else {
            ++it;
        }
    }
}

void MtpMediaLibrary::MoveRepeatDirHandlePathMap(const std::string &from, const std::string &to)
{
    std::string prefix = from + "/";
    for (auto it = pathToHandleMap.begin(); it != pathToHandleMap.end();) {
        if (StartsWith(it->first, prefix)) {
            uint32_t eachId = it->second;
            std::string eachStr = it->first;
            it = pathToHandleMap.erase(it);

            std::string eachSuffixString = eachStr.substr(prefix.size());
            std::string newPath = to + "/" + eachSuffixString;
            pathToHandleMap.emplace(newPath, eachId);

            auto iter = handleToPathMap.find(eachId);
            if (iter != handleToPathMap.end()) {
                handleToPathMap.erase(iter);
                handleToPathMap.emplace(eachId, newPath);
            }
        } else {
            ++it;
        }
    }
    uint32_t originToId = pathToHandleMap[to];
    auto iterator = pathToHandleMap.find(from);
    if (iterator != pathToHandleMap.end()) {
        uint32_t id = iterator->second;
        pathToHandleMap.erase(iterator);
        pathToHandleMap[to] = id;

        auto iter = handleToPathMap.find(id);
        if (iter != handleToPathMap.end()) {
            handleToPathMap.erase(originToId);
            handleToPathMap[id] = to;
        }
    }
}

int32_t MtpMediaLibrary::GetHandles(int32_t parentId, std::vector<int> &outHandles, MediaType mediaType)
{
    MEDIA_DEBUG_LOG("MtpMediaLibrary::GetHandles parent[%{public}d]", parentId);
    std::string path("");
    if (GetPathById(parentId, path) != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpMediaLibrary::GetHandles parent not found");
        return MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR);
    }
    std::shared_ptr<UInt32List> out = std::make_shared<UInt32List>();
    {
        WriteLock lock(g_mutex);
        ScanDirNoDepth(path, out);
    }
    for (const auto &handle : *out) {
        outHandles.push_back(handle);
    }
    return MTP_SUCCESS;
}

int32_t MtpMediaLibrary::GetHandles(const std::shared_ptr<MtpOperationContext> &context,
    std::shared_ptr<UInt32List> &outHandles)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr,
        MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR), "context is nullptr");
    uint32_t parentId = context->parent;
    std::string path("");
    if (GetPathByContextParent(context, path) != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpMediaLibrary::GetHandles parent[%{public}d] not found", parentId);
        return MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR);
    }
    MEDIA_DEBUG_LOG("MtpMediaLibrary::GetHandles path[%{public}s]", path.c_str());
    int32_t errCode;
    {
        WriteLock lock(g_mutex);
        errCode = ScanDirNoDepth(path, outHandles);
    }
    return errCode;
}

uint32_t MtpMediaLibrary::GetParentId(const std::string &path)
{
    ReadLock lock(g_mutex);
    auto parentPath = sf::path(path).parent_path().string();
    auto it = pathToHandleMap.find(parentPath);
    if (it == pathToHandleMap.end()) {
        return 0;
    }
    return it->second;
}

uint32_t MtpMediaLibrary::GetSizeFromOfft(const off_t &size)
{
    return size > std::numeric_limits<uint32_t>::max() ? std::numeric_limits<uint32_t>::max() : size;
}

int32_t MtpMediaLibrary::GetObjectInfo(const std::shared_ptr<MtpOperationContext> &context,
    std::shared_ptr<ObjectInfo> &outObjectInfo)
{
    if (context == nullptr || context->handle <= 0 || outObjectInfo == nullptr) {
        MEDIA_ERR_LOG("handle error");
        return MtpErrorUtils::SolveGetObjectInfoError(E_HAS_DB_ERROR);
    }
    MEDIA_DEBUG_LOG("MtpMediaLibrary::GetObjectInfo storageID[%{public}d]", context->storageID);
    std::string path("");
    if (GetPathById(context->handle, path) != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpMediaLibrary::GetObjectInfo handle not found");
        return MtpErrorUtils::SolveGetObjectInfoError(E_HAS_DB_ERROR);
    }

    outObjectInfo->handle = context->handle;
    outObjectInfo->name = sf::path(path).filename().string();
    outObjectInfo->parent = GetParentId(path);
    outObjectInfo->storageID = context->storageID;
    MtpDataUtils::GetMtpFormatByPath(path, outObjectInfo->format);
    MediaType mediaType;
    MtpDataUtils::GetMediaTypeByformat(outObjectInfo->format, mediaType);
    if (mediaType == MediaType::MEDIA_TYPE_IMAGE || mediaType == MediaType::MEDIA_TYPE_VIDEO) {
        outObjectInfo->thumbCompressedSize = COMPRE_SIZE_LEVEL_2;
        outObjectInfo->thumbFormat = MTP_FORMAT_EXIF_JPEG_CODE;
        outObjectInfo->thumbPixelHeight = NORMAL_HEIGHT;
        outObjectInfo->thumbPixelWidth = NORMAL_WIDTH;
    }

    std::error_code ec;
    if (sf::is_directory(path, ec)) {
        outObjectInfo->format = MTP_FORMAT_ASSOCIATION_CODE;
    }
    struct stat statInfo;
    if (stat(path.c_str(), &statInfo) != 0) {
        MEDIA_ERR_LOG("MtpMediaLibrary::GetObjectInfo stat failed");
        return MtpErrorUtils::SolveGetObjectInfoError(E_HAS_DB_ERROR);
    }
    outObjectInfo->size = GetSizeFromOfft(statInfo.st_size);
    outObjectInfo->dateCreated = statInfo.st_ctime;
    outObjectInfo->dateModified = statInfo.st_mtime;
    return MtpErrorUtils::SolveGetObjectInfoError(E_SUCCESS);
}

int32_t MtpMediaLibrary::GetFd(const std::shared_ptr<MtpOperationContext> &context, int32_t &outFd)
{
    MEDIA_INFO_LOG("MtpMediaLibrary::GetFd");
    CHECK_AND_RETURN_RET_LOG(context != nullptr,
        MtpErrorUtils::SolveGetFdError(E_HAS_DB_ERROR), "context is nullptr");
    std::string realPath("");
    if (GetPathById(context->handle, realPath) != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpMediaLibrary::GetFd handle not found");
        return MtpErrorUtils::SolveGetFdError(E_HAS_DB_ERROR);
    }

    std::error_code ec;
    realPath = sf::weakly_canonical(realPath, ec);
    if (ec.value() != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpMediaLibrary::GetFd normalized realPath failed");
        return MtpErrorUtils::SolveGetFdError(E_HAS_FS_ERROR);
    }
    int mode = sf::exists(realPath, ec) ? O_RDWR : O_RDWR | O_CREAT;
    outFd = open(realPath.c_str(), mode);
    MEDIA_INFO_LOG("MTP:file %{public}s fd %{public}d", realPath.c_str(), outFd);
    if (outFd > 0) {
        return MtpErrorUtils::SolveGetFdError(E_SUCCESS);
    }
    return MtpErrorUtils::SolveGetFdError(E_HAS_FS_ERROR);
}

bool MtpMediaLibrary::CompressImage(PixelMap &pixelMap, std::vector<uint8_t> &data)
{
    PackOption option = {
        .format = THUMBNAIL_FORMAT,
        .quality = THUMBNAIL_MID,
        .numberHint = 1
    };
    data.resize(pixelMap.GetByteCount());

    ImagePacker imagePacker;
    uint32_t errorCode = imagePacker.StartPacking(data.data(), data.size(), option);
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, false, "Failed to StartPacking %{public}d", errorCode);

    errorCode = imagePacker.AddImage(pixelMap);
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, false, "Failed to AddImage %{public}d", errorCode);

    int64_t packedSize = 0;
    errorCode = imagePacker.FinalizePacking(packedSize);
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, false, "Failed to FinalizePacking %{public}d", errorCode);

    data.resize(packedSize);
    return true;
}

int32_t MtpMediaLibrary::GetVideoThumb(const std::shared_ptr<MtpOperationContext> &context,
    std::shared_ptr<UInt8List> &outThumb)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_CONTEXT_IS_NULL, "context is nullptr");

    shared_ptr<AVMetadataHelper> avMetadataHelper = AVMetadataHelperFactory::CreateAVMetadataHelper();
    CHECK_AND_RETURN_RET_LOG(avMetadataHelper != nullptr, MTP_ERROR_NO_THUMBNAIL_PRESENT,
        "avMetadataHelper is nullptr");

    int32_t fd = 0;
    int error = GetFd(context, fd);
    CHECK_AND_RETURN_RET_LOG(error == MTP_SUCCESS, MTP_ERROR_NO_THUMBNAIL_PRESENT, "GetFd failed");

    struct stat64 st;
    int32_t ret = fstat64(fd, &st);
    CondCloseFd(ret != 0, fd);
    CHECK_AND_RETURN_RET_LOG(ret == 0, MTP_ERROR_NO_THUMBNAIL_PRESENT, "Get file state failed, err %{public}d", errno);

    int64_t length = static_cast<int64_t>(st.st_size);
    ret = avMetadataHelper->SetSource(fd, 0, length, AV_META_USAGE_PIXEL_MAP);
    CondCloseFd(ret != 0, fd);
    CHECK_AND_RETURN_RET_LOG(ret == 0, MTP_ERROR_NO_THUMBNAIL_PRESENT, "SetSource failed, ret %{public}d", ret);

    PixelMapParams param = {
        .dstWidth = NORMAL_WIDTH,
        .dstHeight = NORMAL_HEIGHT,
        .colorFormat = PixelFormat::RGBA_8888
    };
    shared_ptr<PixelMap> sPixelMap = avMetadataHelper->FetchFrameYuv(0,
        AVMetadataQueryOption::AV_META_QUERY_NEXT_SYNC, param);
    CondCloseFd(sPixelMap == nullptr, fd);
    CHECK_AND_RETURN_RET_LOG(sPixelMap != nullptr, MTP_ERROR_NO_THUMBNAIL_PRESENT, "sPixelMap is nullptr");

    sPixelMap->SetAlphaType(AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    CloseFd(context, fd);
    bool isCompressImageSuccess = CompressImage(*sPixelMap.get(), *outThumb);
    CHECK_AND_RETURN_RET_LOG(isCompressImageSuccess == true, MTP_ERROR_NO_THUMBNAIL_PRESENT, "CompressImage is fail");
    return MTP_SUCCESS;
}

int32_t MtpMediaLibrary::GetPictureThumb(const std::shared_ptr<MtpOperationContext> &context,
    std::shared_ptr<UInt8List> &outThumb)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_CONTEXT_IS_NULL, "context is nullptr");

    int32_t fd;
    uint32_t errorCode = MTP_SUCCESS;
    errorCode = static_cast<uint32_t>(GetFd(context, fd));
    CHECK_AND_RETURN_RET_LOG(errorCode == MTP_SUCCESS, MTP_ERROR_NO_THUMBNAIL_PRESENT, "GetFd failed");

    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(fd, opts, errorCode);
    CondCloseFd(imageSource == nullptr, fd);
    CHECK_AND_RETURN_RET_LOG(imageSource != nullptr, MTP_ERROR_NO_THUMBNAIL_PRESENT, "imageSource is nullptr");

    DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {
        .width = NORMAL_WIDTH,
        .height = NORMAL_HEIGHT
    };

    std::unique_ptr<PixelMap> cropPixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    CondCloseFd(cropPixelMap == nullptr, fd);
    CHECK_AND_RETURN_RET_LOG(cropPixelMap != nullptr, MTP_ERROR_NO_THUMBNAIL_PRESENT, "cropPixelMap is nullptr");

    CloseFd(context, fd);
    bool isCompressImageSuccess = CompressImage(*cropPixelMap, *outThumb);
    CHECK_AND_RETURN_RET_LOG(isCompressImageSuccess == true, MTP_ERROR_NO_THUMBNAIL_PRESENT, "CompressImage is fail");
    return MTP_SUCCESS;
}

void MtpMediaLibrary::CondCloseFd(const bool condition, const int fd)
{
    if (!condition || fd <= 0) {
        return;
    }
    int32_t ret = close(fd);
    if (ret != MTP_SUCCESS) {
        MEDIA_ERR_LOG("DealFd CloseFd fail!");
    }
}


int32_t MtpMediaLibrary::GetThumb(const std::shared_ptr<MtpOperationContext> &context,
    std::shared_ptr<UInt8List> &outThumb)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_CONTEXT_IS_NULL, "context is nullptr");
    auto it = handleToPathMap.find(context->handle);
    if (it == handleToPathMap.end()) {
        MEDIA_ERR_LOG("MtpMediaLibrary::GetThumb handle not found");
        return MtpErrorUtils::SolveGetObjectInfoError(E_HAS_DB_ERROR);
    }

    uint16_t format;
    MtpDataUtils::GetMtpFormatByPath(it->second, format);
    MediaType mediaType;
    MtpDataUtils::GetMediaTypeByformat(format, mediaType);
    if (mediaType == MediaType::MEDIA_TYPE_IMAGE) {
        return GetPictureThumb(context, outThumb);
    } else if (mediaType == MediaType::MEDIA_TYPE_VIDEO) {
        return GetVideoThumb(context, outThumb);
    }
    return MTP_SUCCESS;
}

int32_t MtpMediaLibrary::SendObjectInfo(const std::shared_ptr<MtpOperationContext> &context,
    uint32_t &outStorageID, uint32_t &outParent, uint32_t &outHandle)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    std::string doc("");
    if (GetPathByContextParent(context, doc) != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpMediaLibrary::SendObjectInfo parent not found");
        return MtpErrorUtils::SolveSendObjectInfoError(E_HAS_DB_ERROR);
    }

    std::string path = doc + "/" + context->name;
    if (context->format == MTP_FORMAT_ASSOCIATION_CODE) {
        std::error_code ec;
        if (!sf::create_directory(path, ec) || ec.value() != MTP_SUCCESS) {
            MEDIA_ERR_LOG("MtpMediaLibrary::SendObjectInfo create dir failed");
            return MtpErrorUtils::SolveSendObjectInfoError(E_HAS_DB_ERROR);
        }
    } else {
        std::error_code ec;
        path = sf::weakly_canonical(path, ec);
        if (ec.value() != MTP_SUCCESS) {
            MEDIA_ERR_LOG("MtpMediaLibrary::SendObjectInfo normalized path failed");
            return MtpErrorUtils::SolveSendObjectInfoError(E_HAS_FS_ERROR);
        }
        std::ofstream ofs(path.c_str());
        if (ofs.is_open()) {
            ofs.close();
        } else {
            MEDIA_ERR_LOG("MtpMediaLibrary::SendObjectInfo create file failed");
            return MtpErrorUtils::SolveSendObjectInfoError(E_HAS_DB_ERROR);
        }
    }

    uint32_t index = GetId();
    {
        WriteLock lock(g_mutex);
        AddToHandlePathMap(path, index);
    }
    outHandle = index;
    outStorageID = context->storageID;
    outParent = context->parent;
    return MtpErrorUtils::SolveSendObjectInfoError(E_SUCCESS);
}

int32_t MtpMediaLibrary::GetPathById(const int32_t id, std::string &outPath)
{
    MEDIA_DEBUG_LOG("MtpMediaLibrary::GetPathById id[%{public}d]", id);
    ReadLock lock(g_mutex);
    auto it = handleToPathMap.find(id);
    if (it != handleToPathMap.end()) {
        outPath = it->second;
        return MTP_SUCCESS;
    }
    return E_ERR;
}

int32_t MtpMediaLibrary::GetPathByContextParent(const std::shared_ptr<MtpOperationContext> &context, std::string &path)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_CONTEXT_IS_NULL, "context is nullptr");
    if (context->parent == 0 || context->parent == MTP_ALL_HANDLE_ID) {
        auto it = storageIdToPathMap.find(context->storageID);
        if (it != storageIdToPathMap.end()) {
            path = it->second;
            return MTP_SUCCESS;
        }
        return E_ERR;
    }
    return GetPathById(context->parent, path);
}

int32_t MtpMediaLibrary::GetIdByPath(const std::string &path, uint32_t &outId)
{
    MEDIA_DEBUG_LOG("MtpMediaLibrary::GetIdByPath path[%{public}s]", path.c_str());
    ReadLock lock(g_mutex);
    auto it = pathToHandleMap.find(path);
    if (it != pathToHandleMap.end()) {
        outId = it->second;
        return E_SUCCESS;
    }
    return E_NO_SUCH_FILE;
}

int32_t MtpMediaLibrary::GetRealPath(const std::string &path, std::string &outPath)
{
    if (PUBLIC_DOC.compare(path.substr(0, PUBLIC_DOC.size())) == 0) {
        uid_t uid = getuid() / BASE_USER_RANGE;
        std::string realPath = PUBLIC_REAL_PATH_PRE + std::to_string(uid) + PUBLIC_REAL_PATH_END;
        outPath = realPath + path.substr(PUBLIC_DOC.size(), path.size());
        return MTP_SUCCESS;
    }
    if (SD_DOC.compare(path.substr(0, SD_DOC.size())) == 0) {
        outPath = path;
        return MTP_SUCCESS;
    }
    MEDIA_ERR_LOG("MtpMediaLibrary::GetRealPath path[%{public}s] error", path.c_str());
    return E_ERR;
}

uint32_t MtpMediaLibrary::MoveObjectSub(const sf::path &fromPath, const sf::path &toPath, const bool &isDir,
    uint32_t &repeatHandle)
{
    auto it = pathToHandleMap.find(toPath.string());
    if (it == pathToHandleMap.end()) {
        if (isDir) {
            MoveHandlePathMap(fromPath.string(), toPath.string());
        }
        ModifyHandlePathMap(fromPath.string(), toPath.string());
    } else {
        if (isDir) {
            uint32_t toHandle = pathToHandleMap.find(toPath.string())->second;
            MoveRepeatDirHandlePathMap(fromPath, toPath);
            repeatHandle = toHandle;
        } else {
            repeatHandle = pathToHandleMap.find(toPath.string())->second;
            auto ite = pathToHandleMap.find(fromPath.string());
            if (ite != pathToHandleMap.end()) {
                ModifyPathHandleMap(toPath.string(), ite->second);
            }
        }
    }
    return MTP_SUCCESS;
}

int32_t MtpMediaLibrary::MoveObject(const std::shared_ptr<MtpOperationContext> &context, uint32_t &repeatHandle)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    std::string from("");
    std::string to("");
    if (GetPathById(context->handle, from) != MTP_SUCCESS || GetPathByContextParent(context, to) != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpMediaLibrary::MoveObject from or to not found");
        return MtpErrorUtils::SolveMoveObjectError(E_HAS_DB_ERROR);
    }

    std::error_code ec;
    if (!sf::exists(from, ec) || !sf::exists(to, ec)) {
        MEDIA_ERR_LOG("MtpMediaLibrary::MoveObject from or to path not found");
        return MtpErrorUtils::SolveMoveObjectError(E_HAS_DB_ERROR);
    }
    if (!sf::is_directory(to, ec)) {
        MEDIA_ERR_LOG("MtpMediaLibrary::MoveObject parent path is not dir");
        return MtpErrorUtils::SolveMoveObjectError(E_HAS_DB_ERROR);
    }
    auto fromPath = sf::path(from);
    auto toPath = sf::path(to) / sf::path(from).filename();
    bool isDir = sf::is_directory(fromPath, ec);
    sf::rename(fromPath, toPath, ec);
    MEDIA_INFO_LOG("MTP:MoveObject:from[%{public}s],to[%{public}s]", fromPath.c_str(), toPath.c_str());
    if (ec.value() != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpMediaLibrary::MoveObject failed");
        return MtpErrorUtils::SolveMoveObjectError(E_FAIL);
    }
    {
        WriteLock lock(g_mutex);
        MoveObjectSub(fromPath, toPath, isDir, repeatHandle);
    }
    return MTP_SUCCESS;
}

int32_t MtpMediaLibrary::CopyObject(const std::shared_ptr<MtpOperationContext> &context,
    uint32_t &outObjectHandle, uint32_t &oldHandle)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    std::string from("");
    std::string to("");
    if (GetPathById(context->handle, from) != MTP_SUCCESS || GetPathByContextParent(context, to) != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpMediaLibrary::CopyObject from or to not found");
        return MtpErrorUtils::SolveMoveObjectError(E_HAS_DB_ERROR);
    }

    if (!sf::exists(from) || !sf::exists(to)) {
        MEDIA_ERR_LOG("MtpMediaLibrary::CopyObject handle or parent path not found");
        return MtpErrorUtils::SolveCopyObjectError(E_HAS_DB_ERROR);
    }
    if (!sf::is_directory(to)) {
        MEDIA_ERR_LOG("MtpMediaLibrary::CopyObject parent path is not dir");
        return MtpErrorUtils::SolveCopyObjectError(E_HAS_DB_ERROR);
    }
    std::error_code ec;
    auto fromPath = sf::path(from);
    auto toPath = sf::path(to) / sf::path(from).filename();
    if (sf::exists(toPath, ec)) {
        MEDIA_ERR_LOG("MtpMediaLibrary::CopyObject toPath exists");
        return MtpErrorUtils::SolveCopyObjectError(E_FILE_EXIST);
    }
    sf::copy(fromPath, toPath, sf::copy_options::recursive | sf::copy_options::overwrite_existing, ec);
    if (ec.value() != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpMediaLibrary::CopyObject failed");
        return MtpErrorUtils::SolveCopyObjectError(E_FAIL);
    }
    auto ret = GetIdByPath(toPath.string(), outObjectHandle);
    {
        WriteLock lock(g_mutex);
        uint32_t index = GetId();
        (ret != E_SUCCESS) ? AddToHandlePathMap(toPath.string(), index) : ModifyPathHandleMap(toPath.string(), index);
        outObjectHandle = index;
        MEDIA_INFO_LOG("CopyObject successful to[%{public}s], handle[%{public}d]", toPath.c_str(), index);
    }
    return MTP_SUCCESS;
}

int32_t MtpMediaLibrary::DeleteObject(const std::shared_ptr<MtpOperationContext> &context)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    std::string path("");
    if (GetPathById(context->handle, path) != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpMediaLibrary::DeleteObject handle not found");
        return MtpErrorUtils::SolveDeleteObjectError(E_HAS_DB_ERROR);
    }
    std::error_code ec;
    if (sf::exists(path, ec) == false) {
        DeleteHandlePathMap(path, context->handle);
        return MTP_SUCCESS;
    }
    MEDIA_DEBUG_LOG("MtpMediaLibrary::DeleteObject path[%{public}s]", path.c_str());
    if (sf::is_directory(path, ec)) {
        sf::remove_all(path, ec);
        if (ec.value() != MTP_SUCCESS) {
            MEDIA_ERR_LOG("MtpMediaLibrary::DeleteObject remove_all failed");
            return MtpErrorUtils::SolveDeleteObjectError(E_HAS_DB_ERROR);
        }
        {
            WriteLock lock(g_mutex);
            ErasePathInfo(context->handle, path);
        }
    } else {
        sf::remove(path, ec);
        if (ec.value() != MTP_SUCCESS) {
            MEDIA_ERR_LOG("MtpMediaLibrary::DeleteObject remove failed");
            return MtpErrorUtils::SolveDeleteObjectError(E_HAS_DB_ERROR);
        }
        DeleteHandlePathMap(path, context->handle);
    }
    return MTP_SUCCESS;
}

int32_t MtpMediaLibrary::SetObjectPropValue(const std::shared_ptr<MtpOperationContext> &context)
{
    MEDIA_INFO_LOG("MtpMediaLibrary::SetObjectPropValue");
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_INVALID_OBJECTHANDLE, "context is nullptr");
    std::string colName;
    variant<int64_t, std::string> colValue;
    int32_t errCode = MtpDataUtils::SolveSetObjectPropValueData(context, colName, colValue);
    CHECK_AND_RETURN_RET_LOG(errCode == 0, errCode, "fail to SolveSetObjectPropValueData");
    if (colName.compare(MEDIA_DATA_DB_PARENT_ID) == 0) {
        return MTP_SUCCESS;
    }
    std::string path("");
    if (GetPathById(context->handle, path) != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpMediaLibrary::SetObjectPropValue handle not found");
        return MtpErrorUtils::SolveObjectPropValueError(E_HAS_DB_ERROR);
    }

    std::error_code ec;
    string to = sf::path(path).parent_path().string() + "/" + get<std::string>(colValue);
    if (sf::exists(to, ec) || ec.value() != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpMediaLibrary::SetObjectPropValue rename failed, file/doc exists");
        return MtpErrorUtils::SolveObjectPropValueError(E_HAS_DB_ERROR);
    }

    sf::rename(path, to, ec);
    if (ec.value() != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpMediaLibrary::SetObjectPropValue rename failed");
        return MtpErrorUtils::SolveObjectPropValueError(E_HAS_DB_ERROR);
    }
    {
        WriteLock lock(g_mutex);
        ModifyHandlePathMap(path, to);
        if (sf::is_directory(to, ec)) {
            MoveHandlePathMap(path, to);
        }
    }
    return MTP_SUCCESS;
}

int32_t MtpMediaLibrary::CloseFd(const std::shared_ptr<MtpOperationContext> &context, int32_t fd)
{
    MEDIA_DEBUG_LOG("MtpMediaLibrary::CloseFd fd=[%{public}d]", fd);
    CHECK_AND_RETURN_RET_LOG(fd > 0, E_ERR, "wrong fd");
    int errCode = close(fd);
    return MtpErrorUtils::SolveCloseFdError(errCode);
}

void MtpMediaLibrary::GetHandles(const uint32_t handle, const std::string &root,
    std::shared_ptr<std::unordered_map<uint32_t, std::string>> &out)
{
    auto it = handleToPathMap.find(handle);
    if (it == handleToPathMap.end()) {
        auto ite = pathToHandleMap.find(root);
        if (ite != pathToHandleMap.end()) {
            out->emplace(ite->second, root);
        }
        return;
    }
    out->emplace(handle, it->second);
}

std::shared_ptr<std::unordered_map<uint32_t, std::string>> MtpMediaLibrary::GetHandlesMap(
    const std::shared_ptr<MtpOperationContext> &context)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, nullptr, "context is nullptr");
    auto handlesMap = std::make_shared<std::unordered_map<uint32_t, std::string>>();
    CHECK_AND_RETURN_RET_LOG(handlesMap != nullptr, nullptr, "handlesMap is nullptr");
    auto it = storageIdToPathMap.find(context->storageID);
    const std::string root = (it == storageIdToPathMap.end()) ? PUBLIC_DOC : it->second;
    if (context->depth == MTP_ALL_DEPTH && (context->handle == 0 || context->handle == MTP_ALL_HANDLE_ID)) {
        context->handle = MTP_ALL_HANDLE_ID;
        context->depth = 0;
    }
    if (context->handle != 0) {
        if (context->depth == 0) {
            if (context->handle == MTP_ALL_HANDLE_ID) {
                ScanDirTraverseWithType(root, handlesMap);
            } else {
                GetHandles(context->handle, root, handlesMap);
            }
        }
        if (context->depth == 1) {
            if (context->handle == MTP_ALL_HANDLE_ID) {
                ScanDirWithType(root, handlesMap);
            } else {
                auto it = handleToPathMap.find(context->handle);
                std::string path = (it == handleToPathMap.end()) ? root : it->second;
                ScanDirWithType(path, handlesMap);
            }
        }
    } else {
        ScanDirWithType(root, handlesMap);
    }
    return handlesMap;
}

int32_t MtpMediaLibrary::GetObjectPropList(const std::shared_ptr<MtpOperationContext> &context,
    std::shared_ptr<std::vector<Property>> &outProps)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_INVALID_OBJECTHANDLE, "context is nullptr");
    if (context->property == 0) {
        if (context->groupCode == 0) {
            MEDIA_ERR_LOG("groupCode error");
            return MTP_ERROR_PARAMETER_NOT_SUPPORTED;
        }
        MEDIA_ERR_LOG("context property = 0");
        return MTP_ERROR_SPECIFICATION_BY_GROUP_UNSUPPORTED;
    }
    if (context->depth == MTP_ALL_DEPTH && (context->handle == 0 || context->handle == MTP_ALL_HANDLE_ID)) {
        context->handle = MTP_ALL_HANDLE_ID;
        context->depth = 0;
    }
    MEDIA_DEBUG_LOG("GetObjectPropList handle[0x%{public}x], depth[0x%{public}x] parent[%{public}d]",
        context->handle, context->depth, context->parent);
    if (!(context->depth == 0 || context->depth == 1)) {
        MEDIA_ERR_LOG("depth error");
        return MTP_ERROR_SPECIFICATION_BY_DEPTH_UNSUPPORTED;
    }

    MEDIA_DEBUG_LOG("GetObjectPropList storageID[%{public}d],format[%{public}d],property[0x%{public}x]",
        context->storageID, context->format, context->property);
    int32_t errCode = MTP_ERROR_INVALID_OBJECTHANDLE;
    {
        WriteLock lock(g_mutex);
        auto handlesMap = GetHandlesMap(context);
        if (handlesMap == nullptr || handlesMap->empty()) {
            MEDIA_ERR_LOG("MtpMediaLibrary::GetObjectPropList out is empty");
            return errCode;
        }
        errCode = MtpDataUtils::GetMtpPropList(handlesMap, pathToHandleMap, context, outProps);
    }
    return errCode;
}

uint32_t MtpMediaLibrary::AddPathToMap(const std::string &path)
{
    uint32_t id;
    auto it = pathToHandleMap.find(path);
    if (it == pathToHandleMap.end()) {
        id = GetId();
        AddToHandlePathMap(path, id);
    } else {
        id = it->second;
    }
    MEDIA_DEBUG_LOG("MtpMediaLibrary::AddPathToMap path[%{public}s] id[%{public}d]", path.c_str(), id);
    return id;
}

uint32_t MtpMediaLibrary::ScanDirWithType(const std::string &root,
    std::shared_ptr<std::unordered_map<uint32_t, std::string>> &out)
{
    MEDIA_INFO_LOG("MtpMediaLibrary::ScanDirWithType root[%{public}s]", root.c_str());
    CHECK_AND_RETURN_RET_LOG(out != nullptr, E_ERR, "out is nullptr");
    CHECK_AND_RETURN_RET_LOG(access(root.c_str(), R_OK) == 0, E_ERR, "access failed root[%{public}s]", root.c_str());
    std::error_code ec;
    if (sf::exists(root, ec) && sf::is_directory(root, ec)) {
        out->emplace(AddPathToMap(root), root);
        for (const auto& entry : sf::directory_iterator(root, ec)) {
            if (ec.value() != MTP_SUCCESS) {
                continue;
            }
            if (sf::is_directory(entry.path(), ec) && IsHiddenDirectory(entry.path().string())) {
                continue;
            }
            out->emplace(AddPathToMap(entry.path().string()), entry.path().string());
        }
    } else if (sf::exists(root, ec) && sf::is_regular_file(root, ec)) {
        out->emplace(AddPathToMap(root), root);
    }
    return MTP_SUCCESS;
}

uint32_t MtpMediaLibrary::ScanDirTraverseWithType(const std::string &root,
    std::shared_ptr<std::unordered_map<uint32_t, std::string>> &out)
{
    MEDIA_INFO_LOG("MtpMediaLibrary::ScanDirTraverseWithType root[%{public}s]", root.c_str());
    CHECK_AND_RETURN_RET_LOG(out != nullptr, E_ERR, "out is nullptr");
    CHECK_AND_RETURN_RET_LOG(access(root.c_str(), R_OK) == 0, E_ERR, "access failed root[%{public}s]", root.c_str());
    std::error_code ec;
    if (sf::exists(root, ec) && sf::is_directory(root, ec)) {
        out->emplace(AddPathToMap(root), root);
        for (const auto& entry : sf::recursive_directory_iterator(root, ec)) {
            if (ec.value() != MTP_SUCCESS) {
                continue;
            }
            if (sf::is_directory(entry.path(), ec) && IsHiddenDirectory(entry.path().string())) {
                continue;
            }
            out->emplace(AddPathToMap(entry.path().string()), entry.path().string());
        }
    } else if (sf::exists(root, ec) && sf::is_regular_file(root, ec)) {
        out->emplace(AddPathToMap(root), root);
    }
    return MTP_SUCCESS;
}

int32_t MtpMediaLibrary::GetObjectPropValue(const std::shared_ptr<MtpOperationContext> &context,
    uint64_t &outIntVal, uint128_t &outLongVal, std::string &outStrVal)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_INVALID_OBJECTHANDLE, "context is nullptr");
    MEDIA_INFO_LOG("MtpMediaLibrary::GetObjectPropValue handle[%{public}d] property[%{public}d]",
        context->handle, context->property);
    std::string path("");
    if (GetPathById(context->handle, path) != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpMediaLibrary::GetObjectPropValue handle not found");
        return MTP_ERROR_INVALID_OBJECTHANDLE;
    }

    if (MTP_PROPERTY_PARENT_OBJECT_CODE == context->property) {
        outIntVal = GetParentId(path);
        return MTP_SUCCESS;
    }

    PropertyValue propValue;
    int32_t errCode = MtpDataUtils::GetMtpPropValue(path, context->property, 0, propValue);
    CHECK_AND_RETURN_RET_LOG(errCode == MTP_SUCCESS, MTP_ERROR_INVALID_OBJECTHANDLE, "fail to get GetMtpPropValue");
    outIntVal = propValue.outIntVal;
    outStrVal = propValue.outStrVal;
    return errCode;
}

int MtpMediaLibrary::GetStorageIds()
{
    auto manager = MtpStorageManager::GetInstance();
    CHECK_AND_RETURN_RET_LOG(manager != nullptr, E_ERR, "MtpStorageManager instance is nullptr");

    auto storage = make_shared<Storage>();
    CHECK_AND_RETURN_RET_LOG(storage != nullptr, E_ERR, "storage is nullptr");
    storage->SetStorageID(INNER_STORAGE_ID);
    storage->SetStorageType(MTP_STORAGE_FIXEDRAM);
    storage->SetFilesystemType(MTP_FILESYSTEM_GENERICHIERARCHICAL);
    storage->SetAccessCapability(MTP_ACCESS_READ_WRITE);
    storage->SetMaxCapacity(manager->GetTotalSize(PUBLIC_DOC));
    storage->SetFreeSpaceInBytes(manager->GetFreeSize(PUBLIC_DOC));
    storage->SetFreeSpaceInObjects(0);
    storage->SetStorageDescription(manager->GetStorageDescription(MTP_STORAGE_FIXEDRAM));
    manager->AddStorage(storage);
    {
        WriteLock lock(g_mutex);
        AddToHandlePathMap(PUBLIC_DOC, DEFAULT_PARENT_ID);
        storageIdToPathMap[INNER_STORAGE_ID] = PUBLIC_DOC;
    }
    return MTP_SUCCESS;
}

void MtpMediaLibrary::GetExternalStorages()
{
    CHECK_AND_RETURN_LOG(access(SD_DOC.c_str(), R_OK) == 0, "access failed [%{public}s]", SD_DOC.c_str());
    std::error_code ec;
    CHECK_AND_RETURN_LOG(sf::exists(SD_DOC, ec) && sf::is_directory(SD_DOC, ec), "SD_DOC is not exists");
    for (const auto& entry : sf::directory_iterator(SD_DOC, ec)) {
        if (!sf::is_directory(entry.path(), ec)) {
            continue;
        }
        MEDIA_INFO_LOG("Mtp GetExternalStorages path[%{public}s]", entry.path().c_str());

        auto it = pathToHandleMap.find(entry.path().string());
        if (it != pathToHandleMap.end()) {
            ErasePathInfo(it->second, it->first);
        }
        uint32_t id = SD_START_ID;
        for (id = SD_START_ID; id <= SD_END_ID; id++) {
            if (handleToPathMap.find(id) == handleToPathMap.end()) {
                break;
            }
        }
        if (id > SD_END_ID) {
            MEDIA_ERR_LOG("MtpMediaLibrary::GetExternalStorages error: too many ext disk");
            return;
        }
        MEDIA_INFO_LOG("Mtp GetExternalStorages id[%{public}d] path[%{public}s]", id, entry.path().c_str());

        auto storage = make_shared<Storage>();
        storage->SetStorageID(id);
        storage->SetStorageType(MTP_STORAGE_REMOVABLERAM);
        storage->SetFilesystemType(MTP_FILESYSTEM_GENERICHIERARCHICAL);
        storage->SetAccessCapability(MTP_ACCESS_READ_WRITE);
        storage->SetMaxCapacity(MtpStorageManager::GetInstance()->GetTotalSize(entry.path().c_str()));
        storage->SetFreeSpaceInBytes(MtpStorageManager::GetInstance()->GetFreeSize(entry.path().c_str()));
        storage->SetFreeSpaceInObjects(0);
        storage->SetStorageDescription(entry.path().filename().string());
        MtpStorageManager::GetInstance()->AddStorage(storage);
        AddToHandlePathMap(entry.path().c_str(), id);
    }
}

void MtpMediaLibrary::ErasePathInfo(const uint32_t handle, const std::string &path)
{
    CHECK_AND_RETURN_LOG(!path.empty(), "path is empty");
    if (handleToPathMap.find(handle) != handleToPathMap.end()) {
        handleToPathMap.erase(handle);
    }
    if (pathToHandleMap.find(path) != pathToHandleMap.end()) {
        pathToHandleMap.erase(path);
    }

    std::string prefix = path + PATH_SEPARATOR;
    const auto size = prefix.size();
    std::vector<std::string> erasePaths;
    for (const auto &it : pathToHandleMap) {
        if (prefix.compare(it.first.substr(0, size)) != 0) {
            continue;
        }
        erasePaths.push_back(std::move(it.first));
        if (handleToPathMap.find(it.second) != handleToPathMap.end()) {
            handleToPathMap.erase(it.second);
        }
    }
    for (const auto &p : erasePaths) {
        if (pathToHandleMap.find(p) != pathToHandleMap.end()) {
            pathToHandleMap.erase(p);
        }
    }
    std::vector<std::string>().swap(erasePaths);
}

} // namespace Media
} // namespace OHOS
