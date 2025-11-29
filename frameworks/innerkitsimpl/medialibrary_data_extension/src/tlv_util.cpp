/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "TLVUtil"
#include "tlv_util.h"

#include <cinttypes>
#include <filesystem>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>

#include "dfx_utils.h"
#include "medialibrary_json_operation.h"
#include "medialibrary_errno.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "unique_fd.h"

namespace OHOS {
namespace Media {
namespace {
const uint32_t TLV_BUFFER_SIZE = 256 * 1024; // 256KB
const std::string TLV_FILE_EXTENSION = ".tlv";
const mode_t CHOWN_RW_USER_GRP = S_IRUSR | S_IWUSR | S_IRGRP;
const std::string MOVING_PHOTO_VIDEO_EDITDATA_DIR = "/moving_photo_video";
} // namespace

static off_t GetFileSize(TlvFile tlvFile)
{
    CHECK_AND_RETURN_RET_LOG(tlvFile >= 0, E_ERR, "fd is not valid");
    struct stat64 st;
    CHECK_AND_RETURN_RET_LOG(fstat(tlvFile, &st) == E_OK, E_ERR, "failed to get file size: %{public}d", errno);
    return st.st_size;
}

off_t TlvUtil::GetCurrentPosition(TlvFile tlvFile)
{
    CHECK_AND_RETURN_RET_LOG(tlvFile >= 0, E_ERR, "tlvFile is invalid");
    off_t currentPos = lseek(tlvFile, 0, SEEK_CUR);
    CHECK_AND_RETURN_RET_LOG(currentPos != E_ERR, E_ERR, "failed to get current position: %{public}d", errno);
    return currentPos;
}

int32_t TlvUtil::ValidateTlvFile(const std::string &tlvFilePath)
{
    CHECK_AND_RETURN_RET_LOG(!tlvFilePath.empty(), E_ERR, "tlvFilePath is empty");
    
    TlvFile tlvFile = open(tlvFilePath.c_str(), O_RDONLY);
    CHECK_AND_RETURN_RET_LOG(tlvFile >= 0, E_ERR, "Failed to open TLV file");
    UniqueFd tlvFileFd(tlvFile);
    
    return ValidateTlvFile(tlvFileFd.Get());
}

int32_t TlvUtil::ValidateTlvFile(TlvFile tlvFile)
{
    CHECK_AND_RETURN_RET_LOG(tlvFile >= 0, E_ERR, "tlvFile is invalid");
    
    TlvNode header;
    ssize_t bytes = read(tlvFile, reinterpret_cast<char*>(&header), sizeof(TlvNode));
    CHECK_AND_RETURN_RET_LOG(bytes == sizeof(TlvNode), E_ERR,
        "Failed to read TLV header, got %zd bytes, expected %zu", bytes, sizeof(TlvNode));
    
    CHECK_AND_RETURN_RET_LOG(header.type == TlvTag::TLV_TAG_HEADER, E_ERR,
        "Invalid TLV header tag: 0x%{public}x, expected: 0x%{public}x",
        header.type, TlvTag::TLV_TAG_HEADER);
    
    off_t fileSize = GetFileSize(tlvFile);
    TlvLength expectedDataSize = fileSize - sizeof(TlvNode);
    
    CHECK_AND_RETURN_RET_LOG(header.length == expectedDataSize, E_ERR,
        "TLV data size mismatch: header says %{public}" PRId64 ", file says %{public}" PRId64,
        header.length, expectedDataSize);
    
    MEDIA_INFO_LOG("TLV file validation passed: tag=0x%{public}x, data_size=%{public}" PRId64,
        header.type, header.length);
    return E_OK;
}

TlvFile TlvUtil::CreateTlvFile(const std::string& tlvPath)
{
    MEDIA_INFO_LOG("CreateTlvFile start");
    CHECK_AND_RETURN_RET_LOG(!tlvPath.empty(), E_ERR, "tlvPath is empty");
    std::string parentPath = MediaFileUtils::GetParentPath(tlvPath);
    if (!MediaFileUtils::IsDirExists(parentPath)) {
        CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CreateDirectory(parentPath), E_ERR,
            "Failed to create directory");
    }
    TlvFile tlvFile = open(tlvPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, CHOWN_RW_USER_GRP);
    CHECK_AND_RETURN_RET_LOG(tlvFile >= 0, E_ERR, "fd is not valid");

    if (WriteTagInfoToTlv(tlvFile, TlvTag::TLV_TAG_HEADER, 0) != E_OK) {
        close(tlvFile);
        MediaFileUtils::DeleteFile(tlvPath);
        MEDIA_ERR_LOG("WriteTagInfoToTlv failed");
        return E_ERR;
    }
    return tlvFile;
}

int32_t TlvUtil::WriteOriginFileToTlv(TlvFile tlvFile, const std::string &srcFilePath, int32_t srcFd)
{
    CHECK_AND_RETURN_RET_LOG(srcFd >= 0, E_ERR, "src file open failed");

    CHECK_AND_RETURN_RET_LOG(WriteFileNameToTlv(tlvFile, srcFilePath) == E_OK, E_ERR,
        "fail to write file name");

    return WriteTaggedFileToTlv(tlvFile, TlvTag::TLV_TAG_ORIGIN, srcFd);
}

int32_t TlvUtil::WriteSourceFileToTlv(TlvFile tlvFile, int32_t srcFd)
{
    return WriteTaggedFileToTlv(tlvFile, TlvTag::TLV_TAG_SOURCE, srcFd);
}

int32_t TlvUtil::WriteMovingPhotoVideoSourceBackFileToTlv(TlvFile tlvFile, int32_t srcFd)
{
    return WriteTaggedFileToTlv(tlvFile, TlvTag::TLV_TAG_MOVING_PHOTO_VIDEO_SOURCE_BACK, srcFd);
}

int32_t TlvUtil::WriteMovingPhotoVideoSourceFileToTlv(TlvFile tlvFile, int32_t srcFd)
{
    return WriteTaggedFileToTlv(tlvFile, TlvTag::TLV_TAG_MOVING_PHOTO_VIDEO_SOURCE, srcFd);
}

int32_t TlvUtil::WriteTaggedFileToTlv(TlvFile tlvFile, TlvTag tag, const std::string &srcFilePath)
{
    MEDIA_INFO_LOG("WriteTaggedFileToTlv start, tag: 0x%{public}x, srcFilePath: %{public}s",
                   tag, srcFilePath.c_str());
    CHECK_AND_RETURN_RET_LOG(tlvFile >= 0, E_ERR, "tlvFile is invalid");
    std::error_code ec;
    CHECK_AND_RETURN_RET_LOG(std::filesystem::exists(srcFilePath, ec), E_ERR, "src file does not exist");
    
    auto srcFd = open(srcFilePath.c_str(), O_RDONLY);
    UniqueFd srcUniqueFd(srcFd);
    CHECK_AND_RETURN_RET_LOG(srcUniqueFd.Get() > 0, E_ERR, "src file open failed");
    return TlvUtil::WriteTaggedFileToTlv(tlvFile, tag, srcUniqueFd.Get());
}

int32_t TlvUtil::WriteTaggedFileToTlv(TlvFile tlvFile, TlvTag tag, int32_t srcFd)
{
    MEDIA_INFO_LOG("WriteTaggedFileToTlv start, tag: 0x%{public}x", tag);
    CHECK_AND_RETURN_RET_LOG(srcFd >= 0, E_ERR, "src file open failed");

    TlvLength outSize = static_cast<TlvLength>(GetFileSize(srcFd));
    CHECK_AND_RETURN_RET_LOG(WriteTagInfoToTlv(tlvFile, tag, outSize) == E_OK, E_ERR,
        "fail to write tag info for tag 0x%{public}x", tag);
    CHECK_AND_RETURN_RET_LOG(WriteDataValueToTlv(tlvFile, srcFd) == E_OK, E_ERR,
        "fail to write file data for tag 0x%{public}x", tag);
    
    MEDIA_INFO_LOG("WriteTaggedFileToTlv end, tag: 0x%{public}x, size: %{public}" PRId64, tag, outSize);
    return E_OK;
}

int32_t TlvUtil::WriteCameraDataToTlv(TlvFile tlvFile, const std::string &srcFilePath)
{
    return WriteTaggedFileToTlv(tlvFile, TlvTag::TLV_TAG_CAMERA, srcFilePath);
}

int32_t TlvUtil::WriteEditDataToTlv(TlvFile tlvFile, const std::string &srcFilePath)
{
    return WriteTaggedFileToTlv(tlvFile, TlvTag::TLV_TAG_EDITDATA, srcFilePath);
}

int32_t TlvUtil::WriteSourceBackFileToTlv(TlvFile tlvFile, int32_t srcFd)
{
    return WriteTaggedFileToTlv(tlvFile, TlvTag::TLV_TAG_SOURCE_BACK, srcFd);
}

int32_t TlvUtil::WriteJsonDataToTlv(TlvFile tlvFile, const std::string &jsonDataPath)
{
    MEDIA_INFO_LOG("WriteJsonDataToTlv start");
    nlohmann::json jsonData;
    CHECK_AND_RETURN_RET_LOG(MediaJsonOperation::CheckPathAndLoadJson(jsonDataPath, jsonData), E_ERR,
        "fail to load json data");
    CHECK_AND_RETURN_RET_LOG(!jsonData.empty(), E_ERR, "json data is empty");
    CHECK_AND_RETURN_RET_LOG(tlvFile >= 0, E_ERR, "tlvFile is invalid");
    
    std::string jsonStr = jsonData.dump();
    TlvLength outSize = static_cast<TlvLength>(jsonStr.size());
    CHECK_AND_RETURN_RET_LOG(WriteTagInfoToTlv(tlvFile, TlvTag::TLV_TAG_JSON, outSize) == E_OK, E_ERR,
        "fail to write json tag info");
    
    auto ret = write(tlvFile, jsonStr.data(), jsonStr.size());
    CHECK_AND_RETURN_RET_LOG(ret > 0, E_ERR, "tlvFile write json data error: %{public}d", errno);
    
    MEDIA_INFO_LOG("WriteJsonDataToTlv end, size: %{public}" PRId64, outSize);
    return E_OK;
}

int32_t TlvUtil::WriteFileNameToTlv(TlvFile tlvFile, const std::string &srcFilePath)
{
    CHECK_AND_RETURN_RET_LOG(tlvFile >= 0, E_ERR, "tlvFile is invalid");
    std::string filename = std::filesystem::path(srcFilePath).filename().string();
    TlvLength outSize = static_cast<TlvLength>(filename.size());
    CHECK_AND_RETURN_RET_LOG(WriteTagInfoToTlv(tlvFile, TlvTag::TLV_TAG_FILENAME, outSize) == E_OK,
        E_ERR, "write file name tag info failed");
    return WriteDataValueToTlv(tlvFile, filename);
}

int32_t TlvUtil::WriteTagInfoToTlv(TlvFile tlvFile, TlvTag tag, TlvLength length)
{
    CHECK_AND_RETURN_RET_LOG(tlvFile >= 0, E_ERR, "tlvFile is invalid");
    TlvNode node = { tag, length };
    auto ret = write(tlvFile, &node, sizeof(TlvNode));
    CHECK_AND_RETURN_RET_LOG(ret > 0, E_ERR, "tlvFile write error [%{public}d]", errno);
    return E_OK;
}

int32_t TlvUtil::WriteDataValueToTlv(TlvFile tlvFile, TlvFile srcFile)
{
    CHECK_AND_RETURN_RET_LOG(tlvFile >= 0, E_ERR, "tlvFile is invalid");
    CHECK_AND_RETURN_RET_LOG(srcFile > 0, E_ERR, "srcFile is invalid");

    char buffer[TLV_BUFFER_SIZE] = {0};
    size_t bytesRead = 0;
    size_t bytesWritten = 0;
    while ((bytesRead = read(srcFile, buffer, sizeof(buffer))) > 0) {
        bytesWritten = write(tlvFile, buffer, bytesRead);
        CHECK_AND_RETURN_RET_LOG(bytesWritten == bytesRead, E_ERR, "failed to write file, errno: %{public}d", errno);
    }
    CHECK_AND_RETURN_RET_LOG(bytesRead >= 0, E_ERR, "failed to write file, errno: %{public}d", errno);
    return E_OK;
}

int32_t TlvUtil::WriteDataValueToTlv(TlvFile tlvFile, const std::string& data)
{
    CHECK_AND_RETURN_RET_LOG(!data.empty(), E_ERR, "data is empty");
    CHECK_AND_RETURN_RET_LOG(tlvFile >= 0, E_ERR, "tlvFile is invalid");
    auto ret = write(tlvFile, data.data(), data.size());
    CHECK_AND_RETURN_RET_LOG(ret > 0, E_ERR, "tlvFile write string value error: %{public}d", errno);
    return E_OK;
}

int32_t TlvUtil::UpdateTlvHeadSize(TlvFile tlvFile)
{
    CHECK_AND_RETURN_RET_LOG(tlvFile >= 0, E_ERR, "tlvFile is invalid");
    
    off_t currentPos = GetCurrentPosition(tlvFile);
    CHECK_AND_RETURN_RET_LOG(currentPos > sizeof(TlvNode), E_ERR,
        "Invalid current position: %{public}lld", (long long)currentPos);
    
    TlvLength totalDataSize = currentPos - sizeof(TlvNode);
    MEDIA_INFO_LOG("Auto calculating TLV data size: currentPos=%{public}" PRId64 ", dataSize=%{public}" PRId64,
        static_cast<int64_t>(currentPos), totalDataSize);
    
    return UpdateTlvHeadSize(tlvFile, totalDataSize);
}

int32_t TlvUtil::UpdateTlvHeadSize(TlvFile tlvFile, TlvLength dataSize)
{
    CHECK_AND_RETURN_RET_LOG(tlvFile >= 0, E_ERR, "tlvFile is invalid");
    off_t originalPos = GetCurrentPosition(tlvFile);
    CHECK_AND_RETURN_RET_LOG(lseek(tlvFile, sizeof(TlvNode::type), SEEK_SET) != E_ERR, E_ERR, "failed to lseek file");
    auto ret = write(tlvFile, &dataSize, sizeof(TlvNode::length));
    CHECK_AND_RETURN_RET_LOG(ret > 0, E_ERR, "failed to update head size [%{public}d]", errno);
    CHECK_AND_RETURN_RET_LOG(lseek(tlvFile, originalPos, SEEK_SET) != E_ERR,
        E_ERR, "failed to restore original position");
    MEDIA_INFO_LOG("TLV head size updated: %{public}" PRId64, dataSize);
    return E_OK;
}

int32_t TlvUtil::ExtractFileData(TlvFile tlvFile, const std::string& outFilePath, TlvLength dataLength)
{
    CHECK_AND_RETURN_RET_LOG(tlvFile >= 0, E_ERR, "tlvFile is invalid");
    TlvFile outTlv = open(outFilePath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, CHOWN_RW_USER_GRP);
    CHECK_AND_RETURN_RET_LOG(outTlv > 0, E_ERR, "outTlv open error %{public}d", errno);
    UniqueFd outTlvFd(outTlv);

    char buffer[TLV_BUFFER_SIZE] = {0};
    TlvLength remaining = dataLength;
    ssize_t bytes = 0;
    while (remaining > 0) {
        size_t toRead = (remaining < TLV_BUFFER_SIZE) ? remaining : TLV_BUFFER_SIZE;
        bytes = read(tlvFile, buffer, toRead);
        CHECK_AND_RETURN_RET_LOG(bytes > 0, E_ERR, "failed to read file data, errno: %{public}d", errno);

        auto bytesWritten = write(outTlvFd.Get(), buffer, bytes);
        CHECK_AND_RETURN_RET_LOG(bytesWritten == bytes, E_ERR,
            "failed to write to output file, errno: %{public}d", errno);

        remaining -= bytes;
    }
    return E_OK;
}

int32_t TlvUtil::ProcessTlvNode(TlvFile tlvFile, TlvNode &node, std::string &currentFilename,
    const std::string &destDir, std::unordered_map<TlvTag, std::string> &extractedFiles)
{
    switch (node.type) {
        case TlvTag::TLV_TAG_FILENAME:
            return ExtractFilename(tlvFile, node.length, currentFilename);
        case TlvTag::TLV_TAG_ORIGIN:
            return ExtractOriginFile(tlvFile, node.length, currentFilename, destDir, extractedFiles);
        case TlvTag::TLV_TAG_SOURCE:
            return ExtractSourceFile(tlvFile, node.length, currentFilename, destDir, extractedFiles);
        case TlvTag::TLV_TAG_CAMERA:
            return ExtractCameraData(tlvFile, node.length, destDir, extractedFiles);
        case TlvTag::TLV_TAG_EDITDATA:
            return ExtractEditData(tlvFile, node.length, destDir, extractedFiles);
        case TlvTag::TLV_TAG_SOURCE_BACK:
            return ExtractSourceBackFile(tlvFile, node.length, currentFilename, destDir, extractedFiles);
        case TlvTag::TLV_TAG_JSON:
            return ExtractJsonData(tlvFile, node.length, destDir, extractedFiles);
        case TlvTag::TLV_TAG_MOVING_PHOTO_VIDEO_SOURCE:
            return ExtractMovingPhotoVideoSourceFile(tlvFile, node.length, currentFilename, destDir, extractedFiles);
        case TlvTag::TLV_TAG_MOVING_PHOTO_VIDEO_SOURCE_BACK:
            return ExtractMovingPhotoVideoSourceBackFile(tlvFile, node.length, currentFilename, destDir,
                extractedFiles);
        default:
            return SkipUnknownField(tlvFile, node.length);
    }
}

int32_t TlvUtil::ExtractFilename(TlvFile tlvFile, TlvLength dataLength, std::string &currentFilename)
{
    CHECK_AND_RETURN_RET_LOG(dataLength > 0, E_ERR, "invalid data length for filename");
    currentFilename.resize(dataLength);
    ssize_t bytes = read(tlvFile, reinterpret_cast<char*>(&currentFilename[0]), dataLength);
    CHECK_AND_RETURN_RET_LOG(bytes > 0, E_ERR, "failed to read fileName, errno: %{public}d", errno);
    MEDIA_INFO_LOG("Extracted filename: %{public}s", currentFilename.c_str());
    return E_OK;
}

int32_t TlvUtil::ExtractOriginFile(TlvFile tlvFile, TlvLength dataLength, const std::string &currentFilename,
    const std::string &destDir, std::unordered_map<TlvTag, std::string> &extractedFiles)
{
    std::string originDir = destDir + "/origin";
    if (!std::filesystem::exists(originDir)) {
        std::filesystem::create_directory(originDir);
    }
    std::string outFilePath = originDir + "/" + (currentFilename.empty() ? "origin_file" : currentFilename);
    MEDIA_INFO_LOG("Extracting origin file to: %{public}s, size: %{public}" PRId64,
        DfxUtils::GetSafePath(outFilePath).c_str(), dataLength);
    CHECK_AND_RETURN_RET_LOG(ExtractFileData(tlvFile, outFilePath, dataLength) == E_OK,
        E_ERR, "failed to extract origin file");
    extractedFiles[TLV_TAG_ORIGIN] = outFilePath;
    return E_OK;
}

int32_t TlvUtil::ExtractSourceFile(TlvFile tlvFile, TlvLength dataLength, const std::string &currentFilename,
    const std::string &destDir, std::unordered_map<TlvTag, std::string> &extractedFiles)
{
    std::string outFilePath = destDir + "/source." + MediaFileUtils::GetExtensionFromPath(currentFilename);
    MEDIA_INFO_LOG("Extracting source file to: %{public}s, size: %{public}" PRId64,
        DfxUtils::GetSafePath(outFilePath).c_str(), dataLength);
    CHECK_AND_RETURN_RET_LOG(ExtractFileData(tlvFile, outFilePath, dataLength) == E_OK,
        E_ERR, "failed to extract source file");
    extractedFiles[TLV_TAG_SOURCE] = outFilePath;
    return E_OK;
}

int32_t TlvUtil::ExtractMovingPhotoVideoSourceFile(TlvFile tlvFile, TlvLength dataLength,
    const std::string &currentFilename, const std::string &destDir,
    std::unordered_map<TlvTag, std::string> &extractedFiles)
{
    std::string realDir = destDir + MOVING_PHOTO_VIDEO_EDITDATA_DIR;
    std::string outFilePath = realDir + "/source." + MediaFileUtils::GetExtensionFromPath(currentFilename);
    MEDIA_INFO_LOG("Extracting moving photo image source file to: %{public}s, size: %{public}" PRId64,
        DfxUtils::GetSafePath(outFilePath).c_str(), dataLength);
    if (!std::filesystem::exists(realDir)) {
        std::filesystem::create_directory(realDir);
    }
    CHECK_AND_RETURN_RET_LOG(ExtractFileData(tlvFile, outFilePath, dataLength) == E_OK,
        E_ERR, "failed to extract source file");
    extractedFiles[TLV_TAG_MOVING_PHOTO_VIDEO_SOURCE] = outFilePath;
    return E_OK;
}

int32_t TlvUtil::ExtractMovingPhotoVideoSourceBackFile(TlvFile tlvFile, TlvLength dataLength,
    const std::string &currentFilename, const std::string &destDir,
    std::unordered_map<TlvTag, std::string> &extractedFiles)
{
    std::string realDir = destDir + MOVING_PHOTO_VIDEO_EDITDATA_DIR;
    std::string outFilePath = realDir + "/source_back." + MediaFileUtils::GetExtensionFromPath(currentFilename);
    MEDIA_INFO_LOG("Extracting moving photo image source file to: %{public}s, size: %{public}" PRId64,
        DfxUtils::GetSafePath(outFilePath).c_str(), dataLength);
    if (!std::filesystem::exists(realDir)) {
        std::filesystem::create_directory(realDir);
    }
    CHECK_AND_RETURN_RET_LOG(ExtractFileData(tlvFile, outFilePath, dataLength) == E_OK,
        E_ERR, "failed to extract source file");
    extractedFiles[TLV_TAG_MOVING_PHOTO_VIDEO_SOURCE_BACK] = outFilePath;
    return E_OK;
}

int32_t TlvUtil::ExtractCameraData(TlvFile tlvFile, TlvLength dataLength, const std::string &destDir,
    std::unordered_map<TlvTag, std::string> &extractedFiles)
{
    std::string outFilePath = destDir + "/camera_edit_data";
    MEDIA_INFO_LOG("Extracting camera edit data to: %{public}s, size: %{public}" PRId64,
        DfxUtils::GetSafePath(outFilePath).c_str(), dataLength);
    CHECK_AND_RETURN_RET_LOG(ExtractFileData(tlvFile, outFilePath, dataLength) == E_OK,
        E_ERR, "failed to extract camera edit data");
    extractedFiles[TLV_TAG_CAMERA] = outFilePath;
    return E_OK;
}

int32_t TlvUtil::ExtractEditData(TlvFile tlvFile, TlvLength dataLength, const std::string &destDir,
    std::unordered_map<TlvTag, std::string> &extractedFiles)
{
    std::string outFilePath = destDir + "/edit_data";
    MEDIA_INFO_LOG("Extracting gallery edit data to: %{public}s, size: %{public}" PRId64,
        DfxUtils::GetSafePath(outFilePath).c_str(), dataLength);
    CHECK_AND_RETURN_RET_LOG(ExtractFileData(tlvFile, outFilePath, dataLength) == E_OK,
        E_ERR, "failed to extract gallery edit data");
    extractedFiles[TLV_TAG_EDITDATA] = outFilePath;
    return E_OK;
}

int32_t TlvUtil::ExtractSourceBackFile(TlvFile tlvFile, TlvLength dataLength, const std::string &currentFilename,
    const std::string &destDir, std::unordered_map<TlvTag, std::string> &extractedFiles)
{
    std::string outFilePath = destDir + "/source_back." + MediaFileUtils::GetExtensionFromPath(currentFilename);
    MEDIA_INFO_LOG("Extracting enhanced image to: %{public}s, size: %{public}" PRId64,
        DfxUtils::GetSafePath(outFilePath).c_str(), dataLength);
    CHECK_AND_RETURN_RET_LOG(ExtractFileData(tlvFile, outFilePath, dataLength) == E_OK,
        E_ERR, "failed to extract enhanced image");
    extractedFiles[TLV_TAG_SOURCE_BACK] = outFilePath;
    return E_OK;
}

int32_t TlvUtil::ExtractJsonData(TlvFile tlvFile, TlvLength dataLength, const std::string &destDir,
    std::unordered_map<TlvTag, std::string> &extractedFiles)
{
    std::string outFilePath = destDir + "/media_info.json";
    MEDIA_INFO_LOG("Extracting JSON data to: %{public}s, size: %{public}" PRId64,
        DfxUtils::GetSafePath(outFilePath).c_str(), dataLength);
    CHECK_AND_RETURN_RET_LOG(ExtractFileData(tlvFile, outFilePath, dataLength) == E_OK,
        E_ERR, "failed to extract JSON data");
    extractedFiles[TLV_TAG_JSON] = outFilePath;
    return E_OK;
}

int32_t TlvUtil::SkipUnknownField(TlvFile tlvFile, TlvLength dataLength)
{
    MEDIA_ERR_LOG("unsupported field type, skipping %{public}" PRId64 " bytes", dataLength);
    if (lseek(tlvFile, dataLength, SEEK_CUR) == E_ERR) {
        MEDIA_ERR_LOG("failed to skip unknown field data");
        return E_ERR;
    }
    return E_OK;
}

int32_t TlvUtil::ExtractTlv(const std::string &tlvFilePath, const std::string &destDir,
    std::unordered_map<TlvTag, std::string> &extractedFiles)
{
    MEDIA_INFO_LOG("ExtractTlv start");
    extractedFiles.clear();
    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::IsFileExists(tlvFilePath), E_ERR, "tlvFilePath is not exist");
    MEDIA_INFO_LOG("ExtractTlv start, tlvFilePath: %{public}s", tlvFilePath.c_str());
    CHECK_AND_RETURN_RET_LOG(ValidateTlvFile(tlvFilePath) == E_OK, E_ERR, "TLV file validation failed");
    if (!std::filesystem::exists(destDir)) {
        std::filesystem::create_directory(destDir);
    }
    TlvFile tlvFile = open(tlvFilePath.c_str(), O_RDONLY);
    CHECK_AND_RETURN_RET_LOG(tlvFile >= 0, E_ERR, "tlvFile is invalid");
    UniqueFd tlvFileFd(tlvFile);
    if (lseek(tlvFileFd.Get(), sizeof(TlvNode), SEEK_SET) == E_ERR) {
        MEDIA_ERR_LOG("Failed to seek past TLV header");
        return E_ERR;
    }
    std::string currentFilename;
    TlvNode node;
    ssize_t bytes = 0;
    int32_t fileCount = 0;
    while ((bytes = read(tlvFileFd.Get(), reinterpret_cast<char*>(&node), sizeof(TlvNode))) > 0) {
        int32_t result = ProcessTlvNode(tlvFileFd.Get(), node, currentFilename, destDir, extractedFiles);
        if (result == E_OK) {
            CHECK_AND_EXECUTE(node.type == TlvTag::TLV_TAG_FILENAME, fileCount++);
        } else {
            MEDIA_ERR_LOG("Failed to process TLV node of type 0x%{public}x", node.type);
        }
    }
    CHECK_AND_RETURN_RET_LOG(bytes >= 0, E_ERR, "failed to read type, errno: %{public}d", errno);
    MEDIA_INFO_LOG("ExtractTlv completed successfully, extracted %{public}d files to: %{public}s",
        fileCount, destDir.c_str());
    return E_OK;
}
} // namespace Media
} // namespace OHOS