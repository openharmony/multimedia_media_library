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
#include "medialibrary_type_const.h"

using namespace std;

namespace OHOS {
namespace Media {
FileUtils::FileUtils() {}

FileUtils::~FileUtils() {}

int FileUtils::DeleteFile(const string &fileName)
{
    int ret = remove(fileName.c_str());
    if (ret < 0) {
        MEDIA_INFO_LOG("DeleteFile fail, ret: %{public}d, errno: %{public}d", ret, errno);
    }
    return ret;
}

bool FileUtils::IsFileExist(const string &fileName)
{
    struct stat statInfo {};
    return ((stat(fileName.c_str(), &statInfo)) == SUCCESS);
}

int32_t FileUtils::SaveImage(const string &filePath, void *output, size_t writeSize)
{
    string filePathTemp = filePath + ".tmp";
    int fd = open(filePathTemp.c_str(), O_CREAT|O_WRONLY|O_TRUNC, 0777);
    if (fd < 0) {
        MEDIA_ERR_LOG("fd.Get() < 0 fd %{public}d errno: %{public}d", fd, errno);
        return E_ERR;
    }
    MEDIA_DEBUG_LOG("filePath: %{private}s, fd: %{public}d", filePath.c_str(), fd);

    int ret = write(fd, output, writeSize);
    close(fd);
    if (ret < 0) {
        MEDIA_ERR_LOG("write fail, ret: %{public}d, errno: %{public}d", ret, errno);
        DeleteFile(filePathTemp);
        return ret;
    }

    ret = rename(filePathTemp.c_str(), filePath.c_str());
    if (ret < 0) {
        MEDIA_ERR_LOG("rename fail, ret: %{public}d, errno: %{public}d", ret, errno);
        DeleteFile(filePathTemp);
        return ret;
    }

    return ret;
}

} // namespace Media
} // namespace OHOS