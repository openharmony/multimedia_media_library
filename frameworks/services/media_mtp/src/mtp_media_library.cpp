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

#include <sys/stat.h>
#include <sys/types.h>
#include <fstream>
#include "mtp_media_library.h"
#include "mtp_data_utils.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "mtp_error_utils.h"
#include "mtp_packet_tools.h"

namespace OHOS {
namespace Media {
namespace {
const std::string PUBLIC_REAL_PATH_PRE               = "/storage/media/";
const std::string PUBLIC_REAL_PATH_END               = "/local/files/Docs";
const std::string PUBLIC_DOC                         = "/storage/media/local/files/Docs";
const std::string SD_DOC                             = "/mnt/data/external";
const std::string RECYCLE_NAME                       = ".Trash";
constexpr const uint32_t BASE_USER_RANGE             = 200000;
static std::unordered_map<uint32_t, std::string> handleToPathMap;
static std::unordered_map<std::string, uint32_t> pathToHandleMap;
enum HANDLE_DEFAULT_ID : uint32_t {
    PUBLIC_DOC_ID = 0,
    SD_DOC_ID,
    START_ID
};
} // namespace

std::atomic<uint32_t> MtpMediaLibrary::id_ = 0;
std::mutex MtpMediaLibrary::mutex_;
std::shared_ptr<MtpMediaLibrary> MtpMediaLibrary::instance_ = nullptr;

MtpMediaLibrary::~MtpMediaLibrary()
{
    id_ = START_ID;
    std::unordered_map<uint32_t, std::string>().swap(handleToPathMap);
    std::unordered_map<std::string, uint32_t>().swap(pathToHandleMap);
}

std::shared_ptr<MtpMediaLibrary> MtpMediaLibrary::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_unique<MtpMediaLibrary>();
            instance_->Init();
        }
    }
    return instance_;
}

void MtpMediaLibrary::Init()
{
    id_ = START_ID;
    std::unordered_map<uint32_t, std::string>().swap(handleToPathMap);
    std::unordered_map<std::string, uint32_t>().swap(pathToHandleMap);
    AddToHandlePathMap(PUBLIC_DOC, PUBLIC_DOC_ID);
    AddToHandlePathMap(SD_DOC, SD_DOC_ID);
}

uint32_t MtpMediaLibrary::GetId()
{
    return id_++;
}

uint32_t MtpMediaLibrary::ScanDirNoDepth(const sf::path &root, std::shared_ptr<UInt32List> &out)
{
    if (!sf::exists(root) || !sf::is_directory(root)) {
        MEDIA_ERR_LOG("MtpMediaLibrary::ScanDirNoDepth root[%{public}s] is not exists", root.c_str());
        return E_ERR;
    }
    for (const auto& entry : sf::directory_iterator(root)) {
        // show not recycle dir
        if (sf::is_directory(entry.path()) && entry.path().filename().string() == RECYCLE_NAME) {
            continue;
        }
        uint32_t id = AddPathToMap(entry.path().string());
        out->push_back(id);
    }
    return MTP_SUCCESS;
}

void MtpMediaLibrary::AddToHandlePathMap(const std::string &path, const uint32_t &id)
{
    if (handleToPathMap.find(id) != handleToPathMap.end()) {
        handleToPathMap.erase(id);
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

void MtpMediaLibrary::ModifyPathHandleMap(const std::string &path, const uint32_t &id)
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
    if (prefix.size() > str.size()) {
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

void MtpMediaLibrary::DeletePathHandleMap(const std::string &path, const uint32_t &id)
{
    pathToHandleMap.erase(path);
    handleToPathMap.erase(id);
    for (auto it = pathToHandleMap.begin(); it != pathToHandleMap.end();) {
        if (StartsWith(it->first, path + "/")) {
            uint32_t originalId = it->second;
            it = pathToHandleMap.erase(it);

            auto it2 = handleToPathMap.find(originalId);
            if (it2 != handleToPathMap.end()) {
                handleToPathMap.erase(it2);
            }
        } else {
            ++it;
        }
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
    auto it = handleToPathMap.find(parentId);
    if (it == handleToPathMap.end()) {
        MEDIA_ERR_LOG("MtpMediaLibrary::GetHandles parent not found");
        return MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR);
    }
    std::shared_ptr<UInt32List> out = std::make_shared<UInt32List>();
    ScanDirNoDepth(std::filesystem::path(it->second), out);
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
    if (context->parent == 0 || context->parent == MTP_ALL_HANDLE_ID) {
        if (context->storageID == DEFAULT_STORAGE_ID) {
            return ScanDirNoDepth(std::filesystem::path(PUBLIC_DOC), outHandles);
        }
        return ScanDirNoDepth(std::filesystem::path(SD_DOC), outHandles);
    }
    auto it = handleToPathMap.find(context->parent);
    if (it == handleToPathMap.end()) {
        MEDIA_ERR_LOG("MtpMediaLibrary::GetHandles parent not found");
        return MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR);
    }
    MEDIA_DEBUG_LOG("MtpMediaLibrary::GetHandles path[%{public}s]", it->second.c_str());
    return ScanDirNoDepth(std::filesystem::path(it->second), outHandles);
}

uint32_t MtpMediaLibrary::GetParentId(const std::string &path)
{
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
    if (context == nullptr || context->handle <= 0) {
        MEDIA_ERR_LOG("handle error");
        return MtpErrorUtils::SolveGetObjectInfoError(E_HAS_DB_ERROR);
    }
    MEDIA_ERR_LOG("MtpMediaLibrary::GetObjectInfo storageID[%{public}d]", context->storageID);
    auto it = handleToPathMap.find(context->handle);
    if (it == handleToPathMap.end()) {
        MEDIA_ERR_LOG("MtpMediaLibrary::GetObjectInfo handle not found");
        return MtpErrorUtils::SolveGetObjectInfoError(E_HAS_DB_ERROR);
    }

    outObjectInfo->handle = context->handle;
    outObjectInfo->name = sf::path(it->second).filename().string();
    outObjectInfo->parent = GetParentId(it->second);
    outObjectInfo->storageID = context->storageID;
    if (sf::is_directory(it->second)) {
        outObjectInfo->format = MTP_FORMAT_ASSOCIATION_CODE;
    }
    struct stat statInfo;
    if (stat(it->second.c_str(), &statInfo) != 0) {
        MEDIA_ERR_LOG("MtpMediaLibrary::GetObjectInfo stat failed");
        return MtpErrorUtils::SolveGetObjectInfoError(E_HAS_FS_ERROR);
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
    auto it = handleToPathMap.find(context->handle);
    if (it == handleToPathMap.end()) {
        MEDIA_ERR_LOG("MtpMediaLibrary::GetFd handle not found");
        return MtpErrorUtils::SolveGetFdError(E_HAS_DB_ERROR);
    }
    std::string realPath = it->second;
    outFd = open(realPath.c_str(), O_RDWR | O_CREAT);
    MEDIA_INFO_LOG("MTP:file %{public}s fd %{public}d", realPath.c_str(), outFd);
    if (outFd > 0) {
        return MtpErrorUtils::SolveGetFdError(E_SUCCESS);
    }
    return MtpErrorUtils::SolveGetFdError(E_HAS_FS_ERROR);
}

int32_t MtpMediaLibrary::GetThumb(const std::shared_ptr<MtpOperationContext> &context,
    std::shared_ptr<UInt8List> &outThumb)
{
    return 0;
}

int32_t MtpMediaLibrary::SendObjectInfo(const std::shared_ptr<MtpOperationContext> &context,
    uint32_t &outStorageID, uint32_t &outParent, uint32_t &outHandle)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    uint32_t parent = context->parent;
    if (parent == MTP_ALL_HANDLE_ID) {
        parent = (context->storageID == DEFAULT_STORAGE_ID) ? PUBLIC_DOC_ID : SD_DOC_ID;
    }
    auto it = handleToPathMap.find(parent);
    if (it == handleToPathMap.end()) {
        MEDIA_ERR_LOG("MtpMediaLibrary::SendObjectInfo parent not found");
        return MtpErrorUtils::SolveSendObjectInfoError(E_HAS_DB_ERROR);
    }
    std::string path = it->second + "/" + context->name;
    if (context->format == MTP_FORMAT_ASSOCIATION_CODE) {
        sf::create_directory(path);
    } else {
        std::ofstream ofs(path.c_str());
        if (ofs.is_open()) {
            ofs.close();
        } else {
            MEDIA_ERR_LOG("MtpMediaLibrary::SendObjectInfo create file failed");
            return MtpErrorUtils::SolveSendObjectInfoError(E_HAS_DB_ERROR);
        }
    }
    uint32_t index = 0;
    index = GetId();
    AddToHandlePathMap(path, index);
    outHandle = index;
    outStorageID = context->storageID;
    outParent = context->parent;
    return MtpErrorUtils::SolveSendObjectInfoError(E_SUCCESS);
}

int32_t MtpMediaLibrary::GetPathById(const int32_t &id, std::string &outPath)
{
    MEDIA_INFO_LOG("MtpMediaLibrary::GetPathById id[%{public}d]", id);
    auto it = handleToPathMap.find(id);
    if (it != handleToPathMap.end()) {
        outPath = it->second;
        return MTP_SUCCESS;
    }
    return E_ERR;
}

int32_t MtpMediaLibrary::GetIdByPath(const std::string &path, uint32_t &outId)
{
    MEDIA_INFO_LOG("MtpMediaLibrary::GetIdByPath path[%{public}s]", path.c_str());
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

int32_t MtpMediaLibrary::MoveObject(const std::shared_ptr<MtpOperationContext> &context, uint32_t &repeatHandle)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    auto handle = handleToPathMap.find(context->handle);
    auto parent = handleToPathMap.find(context->parent);
    if (handle == handleToPathMap.end() || parent == handleToPathMap.end()) {
        MEDIA_ERR_LOG("MtpMediaLibrary::MoveObject handle or parent not found");
        return MtpErrorUtils::SolveMoveObjectError(E_HAS_DB_ERROR);
    }
    if (!sf::exists(handle->second) || !sf::exists(parent->second)) {
        MEDIA_ERR_LOG("MtpMediaLibrary::MoveObject handle or parent path not found");
        return MtpErrorUtils::SolveMoveObjectError(E_HAS_DB_ERROR);
    }
    if (!sf::is_directory(parent->second)) {
        MEDIA_ERR_LOG("MtpMediaLibrary::MoveObject parent path is not dir");
        return MtpErrorUtils::SolveMoveObjectError(E_HAS_DB_ERROR);
    }
    std::error_code ec;
    auto fromPath = sf::path(handle->second);
    auto toPath = sf::path(parent->second) / sf::path(handle->second).filename();
    bool isDir = sf::is_directory(fromPath);
    sf::rename(fromPath, toPath, ec);
    MEDIA_INFO_LOG("MTP:MoveObject:from[%{public}s],to[%{public}s]", fromPath.c_str(), toPath.c_str());
    if (ec.value() != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpMediaLibrary::MoveObject failed");
        return MtpErrorUtils::SolveMoveObjectError(E_FAIL);
    }

    uint32_t fromHandle = pathToHandleMap.find(fromPath.string())->second;
    if (pathToHandleMap.find(toPath.string()) == pathToHandleMap.end()) {
        if (isDir) {
            MoveHandlePathMap(fromPath, toPath);
        }
        ModifyHandlePathMap(fromPath.string(), toPath.string());
    } else {
        if (isDir) {
            uint32_t toHandle = pathToHandleMap.find(toPath.string())->second;
            MoveRepeatDirHandlePathMap(fromPath, toPath);
            repeatHandle = toHandle;
        } else {
            repeatHandle = pathToHandleMap.find(toPath.string())->second;
            ModifyPathHandleMap(toPath.string(), fromHandle);
        }
    }
    return MTP_SUCCESS;
}

int32_t MtpMediaLibrary::CopyObject(const std::shared_ptr<MtpOperationContext> &context,
    uint32_t &outObjectHandle, uint32_t &oldHandle)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    auto handle = handleToPathMap.find(context->handle);
    auto parent = handleToPathMap.find(context->parent);
    if (handle == handleToPathMap.end() || parent == handleToPathMap.end()) {
        MEDIA_ERR_LOG("MtpMediaLibrary::CopyObject handle or parent not found");
        return MtpErrorUtils::SolveCopyObjectError(E_HAS_DB_ERROR);
    }
    if (!sf::exists(handle->second) || !sf::exists(parent->second)) {
        MEDIA_ERR_LOG("MtpMediaLibrary::CopyObject handle or parent path not found");
        return MtpErrorUtils::SolveCopyObjectError(E_HAS_DB_ERROR);
    }
    if (!sf::is_directory(parent->second)) {
        MEDIA_ERR_LOG("MtpMediaLibrary::CopyObject parent path is not dir");
        return MtpErrorUtils::SolveCopyObjectError(E_HAS_DB_ERROR);
    }
    std::error_code ec;
    auto fromPath = sf::path(handle->second);
    auto toPath = sf::path(parent->second) / sf::path(handle->second).filename();
    sf::copy(fromPath, toPath, sf::copy_options::recursive | sf::copy_options::overwrite_existing, ec);
    if (ec.value() != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpMediaLibrary::CopyObject failed");
        return MtpErrorUtils::SolveCopyObjectError(E_FAIL);
    }
    if (pathToHandleMap.find(toPath.string()) != pathToHandleMap.end()) {
        oldHandle = pathToHandleMap.find(toPath.string())->second;
    }
    uint32_t index = 0;
    index = GetId();
    pathToHandleMap.find(toPath.string()) == pathToHandleMap.end() ? AddToHandlePathMap(toPath.string(), index) :
        ModifyPathHandleMap(toPath.string(), index);
    outObjectHandle = index;
    MEDIA_INFO_LOG("CopyObject successful to[%{public}s], handle[%{public}d]", toPath.c_str(), index);
    return MTP_SUCCESS;
}

int32_t MtpMediaLibrary::DeleteObject(const std::shared_ptr<MtpOperationContext> &context)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    auto it = handleToPathMap.find(context->handle);
    if (it == handleToPathMap.end()) {
        MEDIA_ERR_LOG("MtpMediaLibrary::DeleteObject handle not found");
        return MtpErrorUtils::SolveDeleteObjectError(E_HAS_DB_ERROR);
    }
    if (sf::exists(it->second) == false) {
        MEDIA_ERR_LOG("MtpMediaLibrary::DeleteObject path not found");
        return MtpErrorUtils::SolveDeleteObjectError(E_HAS_DB_ERROR);
    }
    MEDIA_INFO_LOG("MtpMediaLibrary::DeleteObject path[%{public}s]", it->second.c_str());
    if (sf::is_directory(it->second)) {
        sf::remove_all(it->second);
        DeletePathHandleMap(it->second, it->first);
    } else {
        sf::remove(it->second);
        pathToHandleMap.erase(it->second);
        handleToPathMap.erase(it->first);
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
    if (colName.compare(MEDIA_DATA_DB_PARENT_ID) != 0) {
        auto it = handleToPathMap.find(context->handle);
        if (it == handleToPathMap.end()) {
            MEDIA_ERR_LOG("MtpMediaLibrary::SetObjectPropValue handle not found");
            return MtpErrorUtils::SolveObjectPropValueError(E_HAS_DB_ERROR);
        }
        string to = sf::path(it->second).parent_path().string() + "/" + get<std::string>(colValue);
        if (sf::exists(to)) {
            MEDIA_ERR_LOG("MtpMediaLibrary::SetObjectPropValue rename failed, file/doc exists");
            return MtpErrorUtils::SolveObjectPropValueError(E_HAS_DB_ERROR);
        }
        sf::rename(it->second, to);
        ModifyHandlePathMap(it->second, to);
    }
    return MTP_SUCCESS;
}

int32_t MtpMediaLibrary::CloseFd(const std::shared_ptr<MtpOperationContext> &context, int32_t fd)
{
    CHECK_AND_RETURN_RET_LOG(fd > 0, E_ERR, "wrong fd");
    int errCode = close(fd);
    return MtpErrorUtils::SolveCloseFdError(errCode);
}

std::shared_ptr<std::unordered_map<uint32_t, std::string>> MtpMediaLibrary::GetHandlesMap(
    const std::shared_ptr<MtpOperationContext> &context)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, nullptr, "context is nullptr");
    auto handlesMap = std::make_shared<std::unordered_map<uint32_t, std::string>>();
    const std::string root = context->storageID == DEFAULT_STORAGE_ID ? PUBLIC_DOC : SD_DOC;
    if (context->depth == MTP_ALL_DEPTH && (context->handle == 0 || context->handle == MTP_ALL_HANDLE_ID)) {
        context->handle = MTP_ALL_HANDLE_ID;
        context->depth = 0;
    }
    if (context->handle != 0) {
        if (context->depth == 0) {
            if (context->handle == MTP_ALL_HANDLE_ID) {
                ScanDirTraverseWithType(std::filesystem::path(root), handlesMap);
            } else {
                ScanDirTraverseWithType(
                    std::filesystem::path(handleToPathMap.find(context->handle)->second), handlesMap);
            }
        }
        if (context->depth == 1) {
            if (context->handle == MTP_ALL_HANDLE_ID) {
                ScanDirWithType(std::filesystem::path(root), handlesMap);
            } else {
                ScanDirWithType(std::filesystem::path(handleToPathMap.find(context->handle)->second), handlesMap);
            }
        }
    } else {
        ScanDirWithType(std::filesystem::path(root), handlesMap);
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
    MEDIA_INFO_LOG("MtpMediaLibrary::GetObjectPropList handle[0x%{public}x], depth[0x%{public}x]",
        context->handle, context->depth);
    if (!(context->depth == 0 || context->depth == 1)) {
        MEDIA_ERR_LOG("depth error");
        return MTP_ERROR_SPECIFICATION_BY_DEPTH_UNSUPPORTED;
    }

    MEDIA_INFO_LOG("MtpMediaLibrary::GetObjectPropList storageID[%{public}d],format[%{public}d],property[0x%{public}x]",
        context->storageID, context->format, context->property);
    auto handlesMap = GetHandlesMap(context);
    if (handlesMap == nullptr || handlesMap->empty()) {
        MEDIA_ERR_LOG("MtpMediaLibrary::GetObjectPropList out is empty");
        return MTP_ERROR_INVALID_OBJECTHANDLE;
    }
    return MtpDataUtils::GetMtpPropList(handlesMap, pathToHandleMap, context, outProps);
}

uint32_t MtpMediaLibrary::AddPathToMap(const sf::path &path)
{
    uint32_t id;
    auto it = pathToHandleMap.find(path);
    if (it == pathToHandleMap.end()) {
        id = GetId();
        AddToHandlePathMap(path.string(), id);
    } else {
        id = it->second;
    }
    MEDIA_DEBUG_LOG("MtpMediaLibrary::AddPathToMap path[%{public}s] id[%{public}d]", path.c_str(), id);
    return id;
}

uint32_t MtpMediaLibrary::ScanDirWithType(const sf::path &root,
    std::shared_ptr<std::unordered_map<uint32_t, std::string>> &out)
{
    CHECK_AND_RETURN_RET_LOG(out != nullptr, E_ERR, "out is nullptr");
    if (sf::exists(root) && sf::is_directory(root)) {
        out->emplace(AddPathToMap(root), root);
        for (const auto& entry : sf::directory_iterator(root)) {
            if (sf::is_directory(entry.path()) && entry.path().filename().string() == RECYCLE_NAME) {
                continue;
            }
            out->emplace(AddPathToMap(entry.path().string()), entry.path().string());
        }
        return MTP_SUCCESS;
    } else if (sf::exists(root) && sf::is_regular_file(root)) {
        out->emplace(AddPathToMap(root), root);
    }
    return E_ERR;
}

uint32_t MtpMediaLibrary::ScanDirTraverseWithType(const sf::path &root,
    std::shared_ptr<std::unordered_map<uint32_t, std::string>> &out)
{
    MEDIA_INFO_LOG("MtpMediaLibrary::ScanDirTraverseWithType root[%{public}s]", root.c_str());
    CHECK_AND_RETURN_RET_LOG(out != nullptr, E_ERR, "out is nullptr");
    if (sf::exists(root) && sf::is_directory(root)) {
        out->emplace(AddPathToMap(root), root);
        for (const auto& entry : sf::recursive_directory_iterator(root)) {
            if (sf::is_directory(entry.path()) && entry.path().filename().string() == RECYCLE_NAME) {
                continue;
            }
            out->emplace(AddPathToMap(entry.path().string()), entry.path().string());
        }
        return MTP_SUCCESS;
    } else if (sf::exists(root) && sf::is_regular_file(root)) {
        out->emplace(AddPathToMap(root), root);
    }
    return E_ERR;
}

int32_t MtpMediaLibrary::GetObjectPropValue(const std::shared_ptr<MtpOperationContext> &context,
    uint64_t &outIntVal, uint128_t &outLongVal, std::string &outStrVal)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_INVALID_OBJECTHANDLE, "context is nullptr");
    MEDIA_INFO_LOG("MtpMediaLibrary::GetObjectPropValue handle[%{public}d] property[%{public}d]",
        context->handle, context->property);
    auto it = handleToPathMap.find(context->handle);
    if (it == handleToPathMap.end()) {
        MEDIA_ERR_LOG("MtpMediaLibrary::GetObjectPropValue handle not found");
        return MTP_ERROR_INVALID_OBJECTHANDLE;
    }

    if (MTP_PROPERTY_PARENT_OBJECT_CODE == context->property) {
        outIntVal = GetParentId(it->second);
        return MTP_SUCCESS;
    }

    PropertyValue propValue;
    int32_t errCode = MtpDataUtils::GetMtpPropValue(it->second, context->property, 0, propValue);
    CHECK_AND_RETURN_RET_LOG(errCode == MTP_SUCCESS, MTP_ERROR_INVALID_OBJECTHANDLE, "fail to get GetMtpPropValue");
    outIntVal = propValue.outIntVal;
    outStrVal = propValue.outStrVal;
    return errCode;
}

} // namespace Media
} // namespace OHOS
