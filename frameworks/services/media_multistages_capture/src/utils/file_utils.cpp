/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "file_utils.h"

#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>

#include "media_log.h"
#include "medialibrary_errno.h"

using namespace std;

namespace OHOS {
namespace Media {
FileUtils::FileUtils() {}

FileUtils::~FileUtils() {}

int32_t FileUtils::SaveImage(const std::string &filePath, void *output, size_t writeSize)
{
    int fd = open(filePath.c_str(), O_CREAT|O_WRONLY|O_TRUNC, 0777);
    if (fd < 0) {
        MEDIA_ERR_LOG("fd.Get() < 0 fd %{public}d errno: %{public}d", fd, errno);
        return E_ERR;
    }
    MEDIA_DEBUG_LOG("filePath: %{private}s, fd: %{public}d", filePath.c_str(), fd);

    int ret = write(fd, output, writeSize);
    close(fd);
    if (ret < 0) {
        MEDIA_ERR_LOG("write fail, errno: %{public}d", errno);
        return ret;
    }
    return E_OK;
}

} // namespace Media
} // namespace OHOS