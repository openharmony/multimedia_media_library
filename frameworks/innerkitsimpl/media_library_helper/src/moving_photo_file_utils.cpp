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

#define MLOG_TAG "MovingPhotoFileUtils"

#include "moving_photo_file_utils.h"

#include <fcntl.h>
#include <regex>
#include <sstream>
#include <sys/sendfile.h>
#include <sys/stat.h>

#include "avmetadatahelper.h"
#include "directory_ex.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_tracer.h"
#include "medialibrary_type_const.h"
#include "string_ex.h"
#include "unique_fd.h"

using namespace std;

namespace OHOS::Media {
const std::string MEDIA_EXTRA_DATA_DIR = "/storage/cloud/files/.editData/";

static int32_t SendLivePhoto(const UniqueFd &livePhotoFd, const string &destPath, int64_t sizeToSend, off_t &offset)
{
    struct stat64 statSrc {};
    CHECK_AND_RETURN_RET_LOG(livePhotoFd.Get() >= 0, livePhotoFd.Get(), "Failed to check src fd of live photo");
    CHECK_AND_RETURN_RET_LOG(fstat64(livePhotoFd.Get(), &statSrc) == 0, E_HAS_FS_ERROR,
        "Failed to get file state of live photo, errno = %{public}d", errno);
    off_t totalSize = statSrc.st_size;
    CHECK_AND_RETURN_RET_LOG(sizeToSend <= totalSize - offset, E_INVALID_LIVE_PHOTO, "Failed to check sizeToSend");

    if (!MediaFileUtils::IsFileExists(destPath) && !MediaFileUtils::CreateFile(destPath)) {
        MEDIA_ERR_LOG("Failed to create file, path:%{private}s", destPath.c_str());
        return E_HAS_FS_ERROR;
    }
    UniqueFd destFd(open(destPath.c_str(), O_WRONLY));
    if (destFd.Get() < 0) {
        MEDIA_ERR_LOG("Failed to open dest path:%{private}s, errno:%{public}d", destPath.c_str(), errno);
        return destFd.Get();
    }

    while (sizeToSend > 0) {
        ssize_t sent = sendfile(destFd.Get(), livePhotoFd.Get(), &offset, sizeToSend);
        if (sent < 0) {
            MEDIA_ERR_LOG("Failed to sendfile with errno=%{public}d", errno);
            return sent;
        }
        sizeToSend -= sent;
    }
    return E_OK;
}

static int32_t GetExtraDataSize(const UniqueFd &livePhotoFd, int64_t &extraDataSize)
{
    struct stat64 st;
    CHECK_AND_RETURN_RET_LOG(fstat64(livePhotoFd.Get(), &st) == 0, E_HAS_FS_ERROR,
        "Failed to get file state of live photo, errno:%{public}d", errno);
    int64_t totalSize = st.st_size;
    CHECK_AND_RETURN_RET_LOG(totalSize > MIN_STANDARD_SIZE, E_INVALID_LIVE_PHOTO,
        "Failed to check live photo, total size is %{public}" PRId64, totalSize);

    char versionTag[VERSION_TAG_LEN + 1];
    CHECK_AND_RETURN_RET_LOG(lseek(livePhotoFd.Get(), -MIN_STANDARD_SIZE, SEEK_END) != -1, E_HAS_FS_ERROR,
        "Failed to lseek version tag, errno:%{public}d", errno);
    CHECK_AND_RETURN_RET_LOG(read(livePhotoFd.Get(), versionTag, VERSION_TAG_LEN) != -1, E_HAS_FS_ERROR,
        "Failed to read version tag, errno:%{public}d", errno);

    uint32_t version = 0;
    uint32_t frameIndex = 0;
    bool hasCinemagraph = false;
    int32_t ret = MovingPhotoFileUtils::GetVersionAndFrameNum(versionTag, version, frameIndex, hasCinemagraph);
    if (ret != E_OK) { // not standard version tag
        extraDataSize = LIVE_TAG_LEN + PLAY_INFO_LEN;
        return E_OK;
    }

    if (!hasCinemagraph) { // extra data without cinemagraph
        extraDataSize = MIN_STANDARD_SIZE;
        return E_OK;
    }

    // extra data with cinemagraph
    CHECK_AND_RETURN_RET_LOG(totalSize > MIN_STANDARD_SIZE + CINEMAGRAPH_INFO_SIZE_LEN, E_INVALID_LIVE_PHOTO,
        "Failed to check live photo with cinemagraph, total size is %{public}" PRId64, totalSize);
    char cinemagraphSize[CINEMAGRAPH_INFO_SIZE_LEN];
    CHECK_AND_RETURN_RET_LOG(lseek(livePhotoFd.Get(), -(MIN_STANDARD_SIZE + CINEMAGRAPH_INFO_SIZE_LEN), SEEK_END) != -1,
        E_HAS_FS_ERROR, "Failed to lseek cinemagraph size, errno:%{public}d", errno);
    CHECK_AND_RETURN_RET_LOG(read(livePhotoFd.Get(), cinemagraphSize, CINEMAGRAPH_INFO_SIZE_LEN) != -1, E_HAS_FS_ERROR,
        "Failed to read cinemagraph size, errno:%{public}d", errno);
    stringstream cinemagraphSizeStream;
    for (int32_t i = 0; i < CINEMAGRAPH_INFO_SIZE_LEN; i++) {
        cinemagraphSizeStream << hex << static_cast<int32_t>(cinemagraphSize[i]);
    }
    const int32_t HEX_BASE = 16;
    extraDataSize = MIN_STANDARD_SIZE + std::stoi(cinemagraphSizeStream.str(), 0, HEX_BASE);
    return E_OK;
}

int32_t MovingPhotoFileUtils::ConvertToMovingPhoto(const std::string &livePhotoPath, const string &movingPhotoImagePath,
    const string &movingPhotoVideoPath, const string &extraDataPath)
{
    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::IsFileExists(livePhotoPath), E_NO_SUCH_FILE,
        "Live photo does not exist, path:%{private}s, errno:%{public}d", livePhotoPath.c_str(), errno);
    CHECK_AND_RETURN_RET_LOG(livePhotoPath.compare(movingPhotoVideoPath) != 0 &&
        livePhotoPath.compare(extraDataPath) != 0, E_INVALID_VALUES,
        "Failed to check dest path of moving photo");
    UniqueFd livePhotoFd(open(livePhotoPath.c_str(), O_RDONLY));
    CHECK_AND_RETURN_RET_LOG(livePhotoFd.Get() >= 0, E_HAS_FS_ERROR,
        "Failed to open live photo:%{private}s, errno:%{public}d", livePhotoPath.c_str(), errno);

    struct stat64 st;
    CHECK_AND_RETURN_RET_LOG(fstat64(livePhotoFd.Get(), &st) == 0, E_HAS_FS_ERROR,
        "Failed to get file state of live photo, errno:%{public}d", errno);
    int64_t totalSize = st.st_size;
    CHECK_AND_RETURN_RET_LOG(totalSize > MIN_STANDARD_SIZE, E_INVALID_LIVE_PHOTO,
        "Failed to check live photo, total size is %{public}" PRId64, totalSize);
    char liveTag[LIVE_TAG_LEN + 1];
    CHECK_AND_RETURN_RET_LOG(lseek(livePhotoFd.Get(), -LIVE_TAG_LEN, SEEK_END) != -1, E_HAS_FS_ERROR,
        "Failed to lseek live tag, errno:%{public}d", errno);
    CHECK_AND_RETURN_RET_LOG(read(livePhotoFd.Get(), liveTag, LIVE_TAG_LEN) != -1, E_HAS_FS_ERROR,
        "Failed to read live tag, errno:%{public}d", errno);

    int64_t extraDataSize = 0;
    int32_t err = GetExtraDataSize(livePhotoFd, extraDataSize);
    CHECK_AND_RETURN_RET_LOG(err == E_OK, E_INVALID_LIVE_PHOTO,
        "Failed to get size of extra data, err:%{public}" PRId64, extraDataSize);
    int64_t liveSize = atoi(liveTag + LIVE_TAG.length());
    int64_t imageSize = totalSize - liveSize - LIVE_TAG_LEN - PLAY_INFO_LEN;
    int64_t videoSize = totalSize - imageSize - extraDataSize;
    CHECK_AND_RETURN_RET_LOG(imageSize > 0 && videoSize > 0, E_INVALID_LIVE_PHOTO,
        "Failed to check live photo, image size:%{public}" PRId64 "video size:%{public}" PRId64, imageSize, videoSize);
    off_t offset = 0;
    bool isSameImagePath = livePhotoPath.compare(movingPhotoImagePath) == 0;
    string tempImagePath = isSameImagePath ? movingPhotoImagePath + ".temp" : movingPhotoImagePath;
    CHECK_AND_RETURN_RET_LOG((err = SendLivePhoto(livePhotoFd, tempImagePath, imageSize, offset)) == E_OK, err,
        "Failed to copy image of live photo");
    CHECK_AND_RETURN_RET_LOG((err = SendLivePhoto(livePhotoFd, movingPhotoVideoPath, videoSize, offset)) == E_OK, err,
        "Failed to copy video of live photo");
    CHECK_AND_RETURN_RET_LOG((err = SendLivePhoto(livePhotoFd, extraDataPath, extraDataSize, offset)) == E_OK, err,
        "Failed to copy extra data of live photo");
    if (isSameImagePath && (err = rename(tempImagePath.c_str(), movingPhotoImagePath.c_str())) < 0) {
        MEDIA_ERR_LOG("Failed to rename moving photo image, ret:%{public}d, errno:%{public}d", err, errno);
        return err;
    }
    return E_OK;
}

static int32_t GetMovingPhotoCoverPosition(const UniqueFd &uniqueFd, const int64_t size,
    const uint32_t frameIndex, uint64_t &coverPosition, int32_t scene)
{
    MediaLibraryTracer tracer;
    tracer.Start("AVMetadataHelper");
    shared_ptr<AVMetadataHelper> helper = AVMetadataHelperFactory::CreateAVMetadataHelper();
    if (helper == nullptr) {
        MEDIA_ERR_LOG("AV metadata helper is null");
        return E_AVMETADATA;
    }

    // notify media_service clone event.
    if (scene == Scene::AV_META_SCENE_CLONE) {
        helper->SetScene(static_cast<Scene>(scene));
    }
    int32_t err = helper->SetSource(uniqueFd.Get(), 0, size, AV_META_USAGE_META_ONLY);
    tracer.Finish();
    if (err != 0) {
        MEDIA_ERR_LOG("SetSource failed for the given fd, err = %{public}d", err);
        return E_AVMETADATA;
    }

    tracer.Start("AVMetadataHelper->GetTimeByFrameIndex");
    err = helper->GetTimeByFrameIndex(frameIndex, coverPosition);
    tracer.Finish();
    if (err != 0) {
        MEDIA_ERR_LOG("Failed to GetTimeByFrameIndex, err = %{public}d", err);
        return E_AVMETADATA;
    }
    return E_OK;
}

int32_t MovingPhotoFileUtils::GetCoverPosition(const std::string &videoPath, const uint32_t frameIndex,
    uint64_t &coverPosition, int32_t scene)
{
    string absVideoPath;
    if (!PathToRealPath(videoPath, absVideoPath)) {
        MEDIA_ERR_LOG("Failed to get real path: %{private}s, errno: %{public}d", videoPath.c_str(), errno);
        return E_HAS_FS_ERROR;
    }

    UniqueFd uniqueFd(open(absVideoPath.c_str(), O_RDONLY));
    if (uniqueFd.Get() < 0) {
        MEDIA_ERR_LOG("Failed to open %{private}s, errno: %{public}d", absVideoPath.c_str(), errno);
        return E_HAS_FS_ERROR;
    }
    struct stat64 st;
    if (fstat64(uniqueFd.Get(), &st) != 0) {
        MEDIA_ERR_LOG("Failed to get file state, errno: %{public}d", errno);
        return E_HAS_FS_ERROR;
    }
    return GetMovingPhotoCoverPosition(uniqueFd, st.st_size, frameIndex, coverPosition, scene);
}

bool EndsWith(const string &str, const string &endStr)
{
    if (str.length() < endStr.length()) {
        return false;
    }
    return str.rfind(endStr) == str.length() - endStr.length();
}

int32_t MovingPhotoFileUtils::GetVersionAndFrameNum(const string &tag,
    uint32_t &version, uint32_t &frameIndex, bool &hasCinemagraphInfo)
{
    static const string VERSION_TAG_REGEX = "^[vV](\\d+)_[fF](\\d+).*";
    std::regex pattern(VERSION_TAG_REGEX);
    std::smatch result;
    if (!std::regex_search(tag, result, pattern)) {
        MEDIA_WARN_LOG("tag is not standard version tag: %{public}s", tag.c_str());
        return E_INVALID_VALUES;
    }

    const int32_t VERSION_POSITION = 1;
    const int32_t FRAME_INDEX_POSITION = 2;
    version = static_cast<uint32_t>(stoi(result[VERSION_POSITION]));
    frameIndex = static_cast<uint32_t>(stoi(result[FRAME_INDEX_POSITION]));
    size_t blankIndex = tag.find_first_of(' ');
    string tagTrimmed = tag;
    if (blankIndex != string::npos) {
        tagTrimmed = tagTrimmed.substr(0, blankIndex);
    }
    hasCinemagraphInfo = EndsWith(tagTrimmed, "_c") || EndsWith(tagTrimmed, "_C");
    return E_OK;
}

int32_t MovingPhotoFileUtils::GetVersionAndFrameNum(int32_t fd,
    uint32_t &version, uint32_t &frameIndex, bool &hasCinemagraphInfo)
{
    CHECK_AND_RETURN_RET_LOG(fd >= 0, E_HAS_FS_ERROR, "Failed to check fd, errno:%{public}d", errno);
    struct stat64 st;
    CHECK_AND_RETURN_RET_LOG(fstat64(fd, &st) == 0, E_HAS_FS_ERROR,
        "Failed to get file state, errno:%{public}d", errno);
    int64_t totalSize = st.st_size;
    CHECK_AND_RETURN_RET_LOG(totalSize > MIN_STANDARD_SIZE, E_INVALID_LIVE_PHOTO,
        "Failed to fetch version tag, total size is %{public}" PRId64, totalSize);

    char versionTag[VERSION_TAG_LEN + 1];
    CHECK_AND_RETURN_RET_LOG(lseek(fd, -MIN_STANDARD_SIZE, SEEK_END) != -1, E_HAS_FS_ERROR,
        "Failed to lseek version tag, errno:%{public}d", errno);
    CHECK_AND_RETURN_RET_LOG(read(fd, versionTag, VERSION_TAG_LEN) != -1, E_HAS_FS_ERROR,
        "Failed to read version tag, errno:%{public}d", errno);
    return MovingPhotoFileUtils::GetVersionAndFrameNum(versionTag, version, frameIndex, hasCinemagraphInfo);
}

string MovingPhotoFileUtils::GetMovingPhotoVideoPath(const string &imagePath)
{
    return MediaFileUtils::GetMovingPhotoVideoPath(imagePath);
}

string MovingPhotoFileUtils::GetMovingPhotoExtraDataDir(const string &imageCloudPath)
{
    if (imageCloudPath.length() < ROOT_MEDIA_DIR.length()) {
        return "";
    }
    return MEDIA_EXTRA_DATA_DIR + imageCloudPath.substr(ROOT_MEDIA_DIR.length());
}

string MovingPhotoFileUtils::GetMovingPhotoExtraDataPath(const string &imageCloudPath)
{
    string parentPath = GetMovingPhotoExtraDataDir(imageCloudPath);
    if (parentPath.empty()) {
        return "";
    }
    return parentPath + "/extraData";
}
} // namespace OHOS::Media