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
#include "database_adapter.h"
#include "result_set_utils.h"
#include "media_column.h"
#include "image_packer.h"
#include "medialibrary_errno.h"
#include "medialibrary_tracer.h"
#include "medialibrary_type_const.h"
#include "medialibrary_operation.h"
#include "medialibrary_object_utils.h"
#include "picture.h"
#include "image_type.h"

using namespace std;

namespace OHOS {
namespace Media {
FileUtils::FileUtils() {}

FileUtils::~FileUtils() {}

int FileUtils::DeleteFile(const string &fileName)
{
    int ret = remove(fileName.c_str());
    if (ret < 0) {
        MEDIA_ERR_LOG("DeleteFile fail, ret: %{public}d, errno: %{public}d", ret, errno);
    }
    return ret;
}

bool FileUtils::IsFileExist(const string &fileName)
{
    struct stat statInfo {};
    return ((stat(fileName.c_str(), &statInfo)) == E_SUCCESS);
}

int32_t FileUtils::SaveImage(const string &filePath, void *output, size_t writeSize)
{
    const mode_t fileMode = 0644;
    MediaLibraryTracer tracer;
    tracer.Start("FileUtils::SaveImage");
    string filePathTemp = filePath + ".high";
    int fd = open(filePathTemp.c_str(), O_CREAT|O_WRONLY|O_TRUNC, fileMode);
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

int32_t FileUtils::SavePicture(const string &imageId, std::shared_ptr<Media::Picture> &picture, bool isEdited)
{
    MediaLibraryTracer tracer;
    // 通过imageid获取fileid 获取uri
    MEDIA_INFO_LOG("photoid: %{public}s", imageId.c_str());
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY);
    string where = PhotoColumn::PHOTO_ID + " = ? ";
    vector<string> whereArgs { imageId };
    cmd.GetAbsRdbPredicates()->SetWhereClause(where);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    vector<string> columns { MediaColumn::MEDIA_ID, MediaColumn::MEDIA_FILE_PATH, PhotoColumn::PHOTO_EDIT_TIME,
        PhotoColumn::PHOTO_SUBTYPE, MediaColumn::MEDIA_MIME_TYPE};
    tracer.Start("Query");
    auto resultSet = DatabaseAdapter::Query(cmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != E_OK) {
        tracer.Finish();
        MEDIA_INFO_LOG("result set is empty");
        return -1;
    }
    tracer.Finish();
    string path = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    int fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    //查询是否编辑 编辑目录下
    string mime_type = GetStringVal(MediaColumn::MEDIA_MIME_TYPE, resultSet);
    if (mime_type == "") {
        mime_type = "image/jpeg";
    }
    Media::ImagePacker imagePacker;
    Media::PackOption packOption;
    packOption.format = mime_type;
    packOption.needsPackProperties = true;
    packOption.desiredDynamicRange = EncodeDynamicRange::AUTO;
    imagePacker.StartPacking(path, packOption);
    imagePacker.AddPicture(*(picture));
    imagePacker.FinalizePacking();
    MediaLibraryObjectUtils::ScanFileAsync(path, to_string(fileId), MediaLibraryApi::API_10);
    MEDIA_INFO_LOG("SavePicture end");
    return 0;
}

int32_t FileUtils::SavePicture(const string &path, std::shared_ptr<Media::Picture> &picture,
    const std::string &mime_type, bool isEdited)
{
    MEDIA_INFO_LOG("SavePicture width %{public}d, heigh %{public}d",
        picture->GetMainPixel()->GetWidth(), picture->GetMainPixel()->GetHeight());
    Media::ImagePacker imagePacker;
    Media::PackOption packOption;
    packOption.format = mime_type;
    packOption.needsPackProperties = true;
    packOption.desiredDynamicRange = EncodeDynamicRange::AUTO;
    imagePacker.StartPacking(path, packOption);

    imagePacker.AddPicture(*(picture));
    imagePacker.FinalizePacking();
    MEDIA_INFO_LOG("SavePicture end");
    return 0;
}
} // namespace Media
} // namespace OHOS