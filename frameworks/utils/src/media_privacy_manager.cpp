/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MediaPrivacyManager"

#include "media_privacy_manager.h"

#include <algorithm>
#include <cerrno>
#include <mntent.h>
#include <securec.h>
#include <unistd.h>
#include <unordered_map>

#include "epfs.h"
#include "image_source.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_type_const.h"
#include "permission_utils.h"

using namespace std;
using PrivacyRanges = vector<pair<uint32_t, uint32_t>>;

namespace OHOS {
namespace Media {

constexpr uint32_t E_NO_EXIF = 1;
constexpr uint32_t E_NO_PRIVACY_EXIF_TAG = 2;

MediaPrivacyManager::MediaPrivacyManager(const string &path, const string &mode) : path_(path), mode_(mode)
{}

MediaPrivacyManager::~MediaPrivacyManager()
{}

const unordered_map<PrivacyType, string> PRIVACY_PERMISSION_MAP = {
    { PrivacyType::PRIVACY_LOCATION, PERMISSION_NAME_MEDIA_LOCATION },
};

const vector<string> EXIF_SUPPORTED_EXTENSION = {
    IMAGE_CONTAINER_TYPE_JPG,
    IMAGE_CONTAINER_TYPE_JPEG,
    IMAGE_CONTAINER_TYPE_JPE
};

static bool IsTargetExtension(const string &path)
{
    const string ext = MediaFileUtils::GetExtensionFromPath(path);
    return find(EXIF_SUPPORTED_EXTENSION.begin(), EXIF_SUPPORTED_EXTENSION.end(), ext) !=
        EXIF_SUPPORTED_EXTENSION.end();
}

static bool IsWriteMode(const string &mode)
{
    return mode.find(MEDIA_FILEMODE_WRITEONLY) != string::npos;
}

static bool CheckFsMounted(const string &fsType, const string &mountPoint)
{
    struct mntent mountEntry;
    constexpr uint32_t mntEntrySize = 1024;
    char entryStr[mntEntrySize] = {0};
    FILE *mountTable = setmntent("/proc/mounts", "r");
    if (mountTable == nullptr) {
        MEDIA_ERR_LOG("Failed to get mount table, errno:%{public}d", errno);
        return false;
    }

    do {
        struct mntent *mnt = getmntent_r(mountTable, &mountEntry, entryStr, sizeof(entryStr));
        if (mnt == nullptr) {
            endmntent(mountTable);
            break;
        }
        if ((mountEntry.mnt_type != nullptr) &&
            (mountEntry.mnt_dir != nullptr) &&
            (strcmp(mountEntry.mnt_type, fsType.c_str()) == 0) &&
            (strcmp(mountEntry.mnt_dir, mountPoint.c_str()) == 0)) {
            endmntent(mountTable);
            return true;
        }
    } while (true);
    return false;
}

static int32_t BindFilterProxyFdToOrigin(const int32_t originFd, int32_t &proxyFd)
{
    int ret = ioctl(proxyFd, IOC_SET_ORIGIN_FD, &originFd);
    if (ret < 0) {
        MEDIA_ERR_LOG("Failed to set origin fd: %{public}d to filter proxy fd: %{public}d, error: %{public}d",
                      originFd, proxyFd, errno);
        return ret;
    }
    return ret;
}

static int32_t SendRangesToIoctl(const int32_t originFd, const int32_t proxyFd, const PrivacyRanges &rans)
{
    FilterProxyRanges *ranges = (FilterProxyRanges *)malloc(sizeof(*ranges) + sizeof(ranges->range[0]) * rans.size());
    if (ranges == nullptr) {
        MEDIA_ERR_LOG("Failed to malloc ranges, errno: %{public}d", errno);
        return -ENOMEM;
    }
    ranges->size = static_cast<uint64_t>(rans.size());
    ranges->reserved = 0;
    for (size_t i = 0; i < rans.size(); i++) {
        // first: offset, second: end
        ranges->range[i].begin = static_cast<uint64_t>(rans[i].first);
        ranges->range[i].end = static_cast<uint64_t>(rans[i].second);
    }
    int err = ioctl(proxyFd, IOC_SET_FILTER_PROXY_RANGE, ranges);
    if (err < 0) {
        MEDIA_ERR_LOG("Failed to set ranges to fd: %{public}d, error: %{public}d", proxyFd, errno);
    }
    free(ranges);
    return err;
}

/* Caller is responsible to close the returned fd */
static int32_t OpenOriginFd(const string &path, const string &mode)
{
    return MediaFileUtils::OpenFile(path, mode);
}

/*
 * Read to the returned @filterProxyFd will redirect to the file specified by @path, but the privacy ranges(@ranges) in
 * read buffer will be filtered out and filled with 0.
 *
 * Caller is responsible to close the returned @filterProxyFd.
 */
static int32_t OpenFilterProxyFd(const string &path, const string &mode, const PrivacyRanges &ranges)
{
    if (!CheckFsMounted(FS_TYPE_EPFS, EPFS_MOUNT_POINT)) {
        MEDIA_INFO_LOG("Epfs is currently not supported yet");
        return OpenOriginFd(path, mode);
    }

    int32_t originFd = open(path.c_str(), O_RDONLY);
    if (originFd < 0) {
        MEDIA_ERR_LOG("Failed to open file, errno: %{public}d, path: %{public}s", errno, path.c_str());
        return originFd;
    }
    constexpr mode_t epfsFileMode = 0400;
    // filterProxyFd_ will be returned to user, so there is no need to close it here.
    int32_t filterProxyFd = open(EPFS_MOUNT_POINT.c_str(), O_TMPFILE | O_RDWR, epfsFileMode);
    if (filterProxyFd < 0) {
        MEDIA_ERR_LOG("Failed to open epfs, error: %{public}d", errno);
        close(originFd);
        return filterProxyFd;
    }
    int32_t ret = BindFilterProxyFdToOrigin(originFd, filterProxyFd);
    if (ret < 0) {
        close(originFd);
        return ret;
    }
    ret = SendRangesToIoctl(originFd, filterProxyFd, ranges);
    if (ret < 0) {
        close(originFd);
        return ret;
    }
    close(originFd);
    MEDIA_INFO_LOG("FilterProxyFd will be returned: %{private}d", filterProxyFd);
    return filterProxyFd;
}

static void ShowRanges(const PrivacyRanges &ranges)
{
    for (auto range : ranges) {
        MEDIA_DEBUG_LOG("Range: [%{public}u, %{public}u)", range.first, range.second);
    }
}

static bool CmpMode(pair<uint32_t, uint32_t> pairA, pair<uint32_t, uint32_t> pairB)
{
    return pairA.first < pairB.first;
}

static int32_t SortRangesAndCheck(PrivacyRanges &ranges)
{
    if (ranges.empty()) {
        return E_SUCCESS;
    }
    uint32_t size = ranges.size();
    if (size > PRIVACY_MAX_RANGES) {
        MEDIA_ERR_LOG("Privacy ranges size invalid: %{public}d", size);
        return -EINVAL;
    }
    sort(ranges.begin(), ranges.end(), CmpMode);

    if (ranges[0].first >= ranges[0].second) {
        MEDIA_ERR_LOG("Incorrect fileter ranges: begin(%{public}u) is not less than end(%{public}u)",
                      ranges[0].first, ranges[0].second);
        return -EINVAL;
    }

    for (uint32_t i = 1; i < size; i++) {
        if ((ranges[i].first >= ranges[i].second) || (ranges[i].first < ranges[i - 1].second)) {
            MEDIA_ERR_LOG("Invalid ranges: [%{public}u, %{public}u), last range is [%{public}u, %{public}u)",
                          ranges[i].first, ranges[i].second, ranges[i - 1].first, ranges[i - 1].second);
            return -EINVAL;
        }
    }
    ShowRanges(ranges);
    return E_SUCCESS;
}

static int32_t CollectRanges(const string &path, const PrivacyType &type, PrivacyRanges &ranges)
{
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    uint32_t err = -1;
    auto imageSource = ImageSource::CreateImageSource(path, opts, err);
    if (imageSource == nullptr) {
        MEDIA_ERR_LOG("Failed to create image source, err: %{public}u", err);
        return -ENOMEM;
    }

    PrivacyRanges areas;
    err = imageSource->GetFilterArea(type, areas);
    if ((err != E_SUCCESS) && (err != E_NO_EXIF) && (err != E_NO_PRIVACY_EXIF_TAG)) {
        MEDIA_ERR_LOG("Failed to get privacy area with type %{public}d, err: %{public}u", type, err);
        return E_ERR;
    }
    for (auto &range : areas) {
        ranges.insert(ranges.end(), std::make_pair(range.first, range.first + range.second));
    }
    return E_SUCCESS;
}

/*
 * @path: [Input], the real path of the target file
 * @mode: [Input], the mode specified by user
 * @ranges: [Output], the privacy ranges of the target file
 *
 * The return value is listed below:
 * o Not a jpeg file: return success with empty ranges
 * o Write jpeg with no MEDIA_LOCATION: return permission denied
 * o Write jpeg with MEDIA_LOCATION: return success with empty ranges
 * o Read jpeg with no MEDIA_LOCATION: return success with privacy ranges if have any
 * o Read jpeg with MEDIA_LOCATION: return success with empty ranges
 * o Other cases: return negative error code.
 */
static int32_t GetPrivacyRanges(const string &path, const string &mode, PrivacyRanges &ranges)
{
    if (!IsTargetExtension(path)) {
        return E_SUCCESS;
    }

    if (mode.find('w') != string::npos) {
        return E_SUCCESS;
    }

    for (auto &item : PRIVACY_PERMISSION_MAP) {
        const string &perm = item.second;
        bool result = PermissionUtils::CheckCallerPermission(perm);
        if ((result == false) && (perm == PERMISSION_NAME_MEDIA_LOCATION) && IsWriteMode(mode)) {
            MEDIA_ERR_LOG("Write is not allowed if have no location permission");
            return E_PERMISSION_DENIED;
        }
        if (result) {
            continue;
        }
        int32_t err = CollectRanges(path, item.first, ranges);
        if (err < 0) {
            return err;
        }
    }
    return SortRangesAndCheck(ranges);
}

int32_t MediaPrivacyManager::Open()
{
    int err = GetPrivacyRanges(path_, mode_, ranges_);
    if (err < 0) {
        return err;
    }
    if (ranges_.size() > 0) {
        return OpenFilterProxyFd(path_, mode_, ranges_);
    }
    return OpenOriginFd(path_, mode_);
}
} // namespace Media
} // namespace OHOS
