/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "utils/file_utils.h"

#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include "media_log.h"

namespace OHOS {
namespace Media {
namespace MediaTool {

bool FileUtils::IsFile(const std::string &path)
{
    if (path.empty()) {
        return false;
    }
    struct stat statInfo = {0};
    if (stat(path.c_str(), &statInfo) == 0) {
        if (statInfo.st_mode & S_IFREG) {
            return true;
        }
    }
    return false;
}

bool FileUtils::SendData(const int rfd, const int wfd)
{
    static const off_t sendSize1G = 1LL * 1024 * 1024 * 1024;
    static const off_t maxSendSize2G = 2LL * 1024 * 1024 * 1024;
    struct stat fst = {0};
    if (fstat(rfd, &fst) != 0) {
        MEDIA_INFO_LOG("send failed, errno=%{public}d", errno);
        return false;
    }
    off_t fileSize = fst.st_size;

    if (fileSize >= maxSendSize2G) {
        off_t offset = 0;
        while (offset < fileSize) {
            off_t sendSize = fileSize - offset;
            if (sendSize > sendSize1G) {
                sendSize = sendSize1G;
            }
            if (sendfile(wfd, rfd, &offset, sendSize) != sendSize) {
                MEDIA_INFO_LOG("send failed, errno=%{public}d", errno);
                return false;
            }
        }
    } else {
        if (sendfile(wfd, rfd, nullptr, fst.st_size) != fileSize) {
            MEDIA_INFO_LOG("send failed, errno=%{public}d", errno);
            return false;
        }
    }
    return true;
}
} // namespace MediaTool
} // namespace Media
} // namespace OHOS
