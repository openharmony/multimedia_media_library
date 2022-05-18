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

#include "mediadata_helper.h"

#include "imediadata.h"
#include "ability_scheduler_interface.h"
#include "ability_thread.h"
#include "abs_shared_result_set.h"
#include "data_ability_observer_interface.h"
#include "data_ability_operation.h"
#include "data_ability_predicates.h"
#include "data_ability_result.h"
#include "hilog_wrapper.h"
#include "imediadata.h"
#include "values_bucket.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string SCHEME_MEDIADATA = "mediadata";
constexpr int INVALID_VALUE = -1;
}  // namespace

std::mutex MediaDataHelper::oplock_;
MediaDataHelper::MediaDataHelper(const std::shared_ptr<OHOS::AbilityRuntime::Context> &context,
    const AAFwk::Want &want)
{
    HILOG_INFO("MediaDataHelper::MediaDataHelper with context and want start");
    token_ = context->GetToken();
    want_ = want;
    uri_ = nullptr;
    mediaDataProxy_ = nullptr;
    mediaDataConnection_ = MediaDataConnection::GetInstance();
    HILOG_INFO("MediaDataHelper::MediaDataHelper with context and want end");
}

MediaDataHelper::MediaDataHelper(const std::shared_ptr<Context> &context, const AAFwk::Want &want,
    const std::shared_ptr<Uri> &uri, const sptr<IMediaData> &mediaDataProxy)
{
    HILOG_INFO("MediaDataHelper::MediaDataHelper start");
    token_ = context->GetToken();
    context_ = std::shared_ptr<Context>(context);
    want_ = want;
    uri_ = uri;
    mediaDataProxy_ = mediaDataProxy;
    mediaDataConnection_ = MediaDataConnection::GetInstance();
    HILOG_INFO("MediaDataHelper::MediaDataHelper end");
}

MediaDataHelper::MediaDataHelper(const std::shared_ptr<OHOS::AbilityRuntime::Context> &context,
    const AAFwk::Want &want, const std::shared_ptr<Uri> &uri, const sptr<IMediaData> &mediaDataProxy)
{
    HILOG_INFO("MediaDataHelper::MediaDataHelper start");
    token_ = context->GetToken();
    want_ = want;
    uri_ = uri;
    mediaDataProxy_ = mediaDataProxy;
    mediaDataConnection_ = MediaDataConnection::GetInstance();
    HILOG_INFO("MediaDataHelper::MediaDataHelper end");
}

void MediaDataHelper::AddMediaDataDeathRecipient(const sptr<IRemoteObject> &token)
{
    HILOG_INFO("MediaDataHelper::AddMediaDataDeathRecipient start.");
    if (token != nullptr && callerDeathRecipient_ != nullptr) {
        HILOG_INFO("token RemoveDeathRecipient.");
        token->RemoveDeathRecipient(callerDeathRecipient_);
    }
    if (callerDeathRecipient_ == nullptr) {
        callerDeathRecipient_ =
            new MediaDataDeathRecipient(std::bind(&MediaDataHelper::OnSchedulerDied, this, std::placeholders::_1));
    }
    if (token != nullptr) {
        HILOG_INFO("token AddDeathRecipient.");
        token->AddDeathRecipient(callerDeathRecipient_);
    }
    HILOG_INFO("MediaDataHelper::AddMediaDataDeathRecipient end.");
}

void MediaDataHelper::OnSchedulerDied(const wptr<IRemoteObject> &remote)
{
    HILOG_INFO("'%{public}s start':", __func__);
    auto object = remote.promote();
    object = nullptr;
    mediaDataProxy_ = nullptr;
    uri_ = nullptr;
    HILOG_INFO("MediaDataHelper::OnSchedulerDied end.");
}

/**
 * @brief Creates a MediaDataHelper instance without specifying the Uri based on the given Context.
 *
 * @param context Indicates the Context object on OHOS.
 * @param want Indicates the Want containing information about the target extension ability to connect.
 *
 * @return Returns the created MediaDataHelper instance where Uri is not specified.
 */
std::shared_ptr<MediaDataHelper> MediaDataHelper::Creator(
    const std::shared_ptr<OHOS::AbilityRuntime::Context> &context, const AAFwk::Want &want)
{
    HILOG_INFO("MediaDataHelper::Creator with context start.");
    if (context == nullptr) {
        HILOG_ERROR("MediaDataHelper::Creator (context) failed, context == nullptr");
        return nullptr;
    }

    HILOG_INFO("MediaDataHelper::Creator before ConnectMediaDataExtAbility.");
    sptr<MediaDataConnection> mediaDataConnection = MediaDataConnection::GetInstance();
    if (!mediaDataConnection->IsExtAbilityConnected()) {
        mediaDataConnection->ConnectMediaDataExtAbility(want, context->GetToken());
    }
    HILOG_INFO("MediaDataHelper::Creator after ConnectMediaDataExtAbility.");

    MediaDataHelper *ptrMediaDataHelper = new (std::nothrow) MediaDataHelper(context, want);
    if (ptrMediaDataHelper == nullptr) {
        HILOG_ERROR("MediaDataHelper::Creator (context) failed, create MediaDataHelper failed");
        return nullptr;
    }

    HILOG_INFO("MediaDataHelper::Creator with context end.");
    return std::shared_ptr<MediaDataHelper>(ptrMediaDataHelper);
}

/**
 * @brief You can use this method to specify the Uri of the data to operate and set the binding relationship
 * between the ability using the Data template (data share for short) and the associated client process in
 * a MediaDataHelper instance.
 *
 * @param context Indicates the Context object on OHOS.
 * @param want Indicates the Want containing information about the target extension ability to connect.
 * @param uri Indicates the database table or disk file to operate.
 *
 * @return Returns the created MediaDataHelper instance.
 */
std::shared_ptr<MediaDataHelper> MediaDataHelper::Creator(
    const std::shared_ptr<OHOS::AppExecFwk::Context> &context, const AAFwk::Want &want, const std::shared_ptr<Uri> &uri)
{
    HILOG_INFO("MediaDataHelper::Creator with context, want and uri called start.");
    if (context == nullptr) {
        HILOG_ERROR("MediaDataHelper::Creator failed, context == nullptr");
        return nullptr;
    }

    if (uri == nullptr) {
        HILOG_ERROR("MediaDataHelper::Creator failed, uri == nullptr");
        return nullptr;
    }

    if (uri->GetScheme() != SCHEME_MEDIADATA) {
        HILOG_ERROR("MediaDataHelper::Creator failed, the Scheme is not mediadata, Scheme: %{public}s",
            uri->GetScheme().c_str());
        return nullptr;
    }

    HILOG_INFO("MediaDataHelper::Creator before ConnectMediaDataExtAbility.");
    sptr<IMediaData> mediaDataProxy = nullptr;

    sptr<MediaDataConnection> mediaDataConnection = MediaDataConnection::GetInstance();
    if (!mediaDataConnection->IsExtAbilityConnected()) {
        mediaDataConnection->ConnectMediaDataExtAbility(want, context->GetToken());
    }
    mediaDataProxy = mediaDataConnection->GetMediaDataProxy();
    if (mediaDataProxy == nullptr) {
        HILOG_WARN("MediaDataHelper::Creator get invalid mediaDataProxy");
    }
    HILOG_INFO("MediaDataHelper::Creator after ConnectMediaDataExtAbility.");

    MediaDataHelper *ptrMediaDataHelper = new (std::nothrow) MediaDataHelper(context, want, uri, mediaDataProxy);
    if (ptrMediaDataHelper == nullptr) {
        HILOG_ERROR("MediaDataHelper::Creator failed, create MediaDataHelper failed");
        return nullptr;
    }

    HILOG_INFO("MediaDataHelper::Creator with context, want and uri called end.");
    return std::shared_ptr<MediaDataHelper>(ptrMediaDataHelper);
}

/**
 * @brief You can use this method to specify the Uri of the data to operate and set the binding relationship
 * between the ability using the Data template (data share for short) and the associated client process in
 * a MediaDataHelper instance.
 *
 * @param context Indicates the Context object on OHOS.
 * @param want Indicates the Want containing information about the target extension ability to connect.
 * @param uri Indicates the database table or disk file to operate.
 *
 * @return Returns the created MediaDataHelper instance.
 */
std::shared_ptr<MediaDataHelper> MediaDataHelper::Creator(
    const std::shared_ptr<OHOS::AbilityRuntime::Context> &context, const AAFwk::Want &want,
    const std::shared_ptr<Uri> &uri)
{
    HILOG_INFO("MediaDataHelper::Creator with runtime context, want and uri called start.");
    if (context == nullptr) {
        HILOG_ERROR("MediaDataHelper::Creator failed, context == nullptr");
        return nullptr;
    }

    if (uri == nullptr) {
        HILOG_ERROR("MediaDataHelper::Creator failed, uri == nullptr");
        return nullptr;
    }
    /*
    if (uri->GetScheme() != SCHEME_MEDIADATA) {
        HILOG_ERROR("MediaDataHelper::Creator failed, the Scheme is not mediadata, Scheme: %{public}s",
            uri->GetScheme().c_str());
        return nullptr;
    }
    */

    HILOG_INFO("MediaDataHelper::Creator before ConnectMediaDataExtAbility.");
    sptr<IMediaData> mediaDataProxy = nullptr;

    sptr<MediaDataConnection> mediaDataConnection = MediaDataConnection::GetInstance();
    if (!mediaDataConnection->IsExtAbilityConnected()) {
        mediaDataConnection->ConnectMediaDataExtAbility(want, context->GetToken());
    }
    mediaDataProxy = mediaDataConnection->GetMediaDataProxy();
    if (mediaDataProxy == nullptr) {
        HILOG_WARN("MediaDataHelper::Creator get invalid mediaDataProxy");
    }
    HILOG_INFO("MediaDataHelper::Creator after ConnectMediaDataExtAbility.");

    MediaDataHelper *ptrMediaDataHelper = new (std::nothrow) MediaDataHelper(context, want, uri, mediaDataProxy);
    if (ptrMediaDataHelper == nullptr) {
        HILOG_ERROR("MediaDataHelper::Creator failed, create MediaDataHelper failed");
        return nullptr;
    }

    HILOG_INFO("MediaDataHelper::Creator with runtime context, want and uri called end.");
    return std::shared_ptr<MediaDataHelper>(ptrMediaDataHelper);
}

MediaDataHelper::MediaDataHelper(const sptr<IRemoteObject> &token, const std::shared_ptr<Uri> &uri,
   const sptr<IMediaData> &mediaDataProxy)
{
    HILOG_DEBUG("MediaDataHelper::MediaDataHelper token start!");
    token_ = token;
    uri_ = uri;
    mediaDataProxy_ = mediaDataProxy;
    mediaDataConnection_ = MediaDataConnection::GetInstance();
    HILOG_DEBUG("MediaDataHelper::MediaDataHelper token end!");
}

std::shared_ptr<MediaDataHelper> MediaDataHelper::Creator(
    const sptr<IRemoteObject> &token, const AAFwk::Want &want, const std::shared_ptr<Uri> &uri)
{
    HILOG_DEBUG("MediaDataHelper::Creator with token uri called start.");
    if (token == nullptr) {
        HILOG_ERROR("MediaDataHelper::Creator (token, uri) failed, token == nullptr");
        return nullptr;
    }

    if (uri == nullptr) {
        HILOG_ERROR("MediaDataHelper::Creator (token, uri) failed, uri == nullptr");
        return nullptr;
    }

    HILOG_DEBUG("MediaDataHelper::Creator before AcquireDataAbility.");
    sptr<MediaDataConnection> mediaDataConnection = MediaDataConnection::GetInstance();
    if (!mediaDataConnection->IsExtAbilityConnected()) {
        mediaDataConnection->ConnectMediaDataExtAbility(want, token);
    }

    sptr<IMediaData> mediaDataProxy = mediaDataConnection->GetMediaDataProxy();

    if (mediaDataProxy == nullptr) {
        HILOG_WARN("MediaDataHelper::Creator get invalid mediaDataProxy");
    }
    HILOG_DEBUG("MediaDataHelper::Creator after AcquireDataAbility.");

    MediaDataHelper *ptrMediaDataHelper = new (std::nothrow) MediaDataHelper(token, uri, mediaDataProxy);
    if (ptrMediaDataHelper == nullptr) {
        HILOG_ERROR("MediaDataHelper::Creator (token, uri) failed, create MediaDataHelper failed");
        return nullptr;
    }

    HILOG_DEBUG("MediaDataHelper::Creator with token uri called end.");
    return std::shared_ptr<MediaDataHelper>(ptrMediaDataHelper);
}

/**
 * @brief Releases the client resource of the data share.
 * You should call this method to releases client resource after the data operations are complete.
 *
 * @return Returns true if the resource is successfully released; returns false otherwise.
 */
bool MediaDataHelper::Release()
{
    HILOG_INFO("MediaDataHelper::Release start.");
    if (uri_ == nullptr) {
        HILOG_ERROR("MediaDataHelper::Release failed, uri_ is nullptr");
        return false;
    }

    HILOG_INFO("MediaDataHelper::Release before DisconnectMediaDataExtAbility.");
    if (mediaDataConnection_->IsExtAbilityConnected()) {
        mediaDataConnection_->DisconnectMediaDataExtAbility();
    }
    HILOG_INFO("MediaDataHelper::Release after DisconnectMediaDataExtAbility.");
    mediaDataProxy_ = nullptr;
    uri_.reset();
    HILOG_INFO("MediaDataHelper::Release end.");
    return true;
}

/**
 * @brief Obtains the MIME types of files supported.
 *
 * @param uri Indicates the path of the files to obtain.
 * @param mimeTypeFilter Indicates the MIME types of the files to obtain. This parameter cannot be null.
 *
 * @return Returns the matched MIME types. If there is no match, null is returned.
 */
std::vector<std::string> MediaDataHelper::GetFileTypes(Uri &uri, const std::string &mimeTypeFilter)
{
    HILOG_INFO("MediaDataHelper::GetFileTypes start.");
    std::vector<std::string> matchedMIMEs;
    if (!CheckUriParam(uri)) {
        HILOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return matchedMIMEs;
    }

    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::GetFileTypes before ConnectMediaDataExtAbility.");
        if (!mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->ConnectMediaDataExtAbility(want_, token_);
        }
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
        HILOG_INFO("MediaDataHelper::GetFileTypes after ConnectMediaDataExtAbility.");
        if (isSystemCaller_ && mediaDataProxy_) {
            AddMediaDataDeathRecipient(mediaDataProxy_->AsObject());
        }
    } else {
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
    }

    if (mediaDataProxy_ == nullptr) {
        HILOG_ERROR("%{public}s failed with invalid mediaDataProxy_", __func__);
        return matchedMIMEs;
    }

    HILOG_INFO("MediaDataHelper::GetFileTypes before mediaDataProxy_->GetFileTypes.");
    matchedMIMEs = mediaDataProxy_->GetFileTypes(uri, mimeTypeFilter);
    HILOG_INFO("MediaDataHelper::GetFileTypes after mediaDataProxy_->GetFileTypes.");
    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::GetFileTypes before DisconnectMediaDataExtAbility.");
        if (mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->DisconnectMediaDataExtAbility();
        }
        HILOG_INFO("MediaDataHelper::GetFileTypes after DisconnectMediaDataExtAbility.");
        mediaDataProxy_ = nullptr;
    }

    HILOG_INFO("MediaDataHelper::GetFileTypes end.");
    return matchedMIMEs;
}

/**
 * @brief Opens a file in a specified remote path.
 *
 * @param uri Indicates the path of the file to open.
 * @param mode Indicates the file open mode, which can be "r" for read-only access, "w" for write-only access
 * (erasing whatever data is currently in the file), "wt" for write access that truncates any existing file,
 * "wa" for write-only access to append to any existing data, "rw" for read and write access on any existing data,
 *  or "rwt" for read and write access that truncates any existing file.
 *
 * @return Returns the file descriptor.
 */
int MediaDataHelper::OpenFile(Uri &uri, const std::string &mode)
{
    HILOG_INFO("MediaDataHelper::OpenFile start.");
    int fd = INVALID_VALUE;
    if (!CheckUriParam(uri)) {
        HILOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return fd;
    }

    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::OpenFile before ConnectMediaDataExtAbility.");
        if (!mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->ConnectMediaDataExtAbility(want_, token_);
        }
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
        HILOG_INFO("MediaDataHelper::OpenFile after ConnectMediaDataExtAbility.");
        if (isSystemCaller_ && mediaDataProxy_) {
            AddMediaDataDeathRecipient(mediaDataProxy_->AsObject());
        }
    } else {
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
    }

    if (mediaDataProxy_ == nullptr) {
        HILOG_ERROR("%{public}s failed with invalid mediaDataProxy_", __func__);
        return fd;
    }

    HILOG_INFO("MediaDataHelper::OpenFile before mediaDataProxy_->OpenFile.");
    fd = mediaDataProxy_->OpenFile(uri, mode);
    HILOG_INFO("MediaDataHelper::OpenFile after mediaDataProxy_->OpenFile.");
    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::OpenFile before DisconnectMediaDataExtAbility.");
        if (mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->DisconnectMediaDataExtAbility();
        }
        HILOG_INFO("MediaDataHelper::OpenFile after DisconnectMediaDataExtAbility.");
        mediaDataProxy_ = nullptr;
    }
    HILOG_INFO("MediaDataHelper::OpenFile end.");
    return fd;
}

/**
 * @brief This is like openFile, open a file that need to be able to return sub-sections of files，often assets
 * inside of their .hap.
 *
 * @param uri Indicates the path of the file to open.
 * @param mode Indicates the file open mode, which can be "r" for read-only access, "w" for write-only access
 * (erasing whatever data is currently in the file), "wt" for write access that truncates any existing file,
 * "wa" for write-only access to append to any existing data, "rw" for read and write access on any existing
 * data, or "rwt" for read and write access that truncates any existing file.
 *
 * @return Returns the RawFileDescriptor object containing file descriptor.
 */
int MediaDataHelper::OpenRawFile(Uri &uri, const std::string &mode)
{
    HILOG_INFO("MediaDataHelper::OpenRawFile start.");
    int fd = INVALID_VALUE;
    if (!CheckUriParam(uri)) {
        HILOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return fd;
    }

    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::OpenRawFile before ConnectMediaDataExtAbility.");
        if (!mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->ConnectMediaDataExtAbility(want_, token_);
        }
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
        HILOG_INFO("MediaDataHelper::OpenRawFile after ConnectMediaDataExtAbility.");
        if (isSystemCaller_ && mediaDataProxy_) {
            AddMediaDataDeathRecipient(mediaDataProxy_->AsObject());
        }
    } else {
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
    }

    if (mediaDataProxy_ == nullptr) {
        HILOG_ERROR("%{public}s failed with invalid mediaDataProxy_", __func__);
        return fd;
    }

    HILOG_INFO("MediaDataHelper::OpenRawFile before mediaDataProxy_->OpenRawFile.");
    fd = mediaDataProxy_->OpenRawFile(uri, mode);
    HILOG_INFO("MediaDataHelper::OpenRawFile after mediaDataProxy_->OpenRawFile.");
    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::OpenRawFile before DisconnectMediaDataExtAbility.");
        if (mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->DisconnectMediaDataExtAbility();
        }
        HILOG_INFO("MediaDataHelper::OpenRawFile after DisconnectMediaDataExtAbility.");
        mediaDataProxy_ = nullptr;
    }
    HILOG_INFO("MediaDataHelper::OpenRawFile end.");
    return fd;
}

/**
 * @brief Inserts a single data record into the database.
 *
 * @param uri Indicates the path of the data to operate.
 * @param value Indicates the data record to insert. If this parameter is null, a blank row will be inserted.
 *
 * @return Returns the index of the inserted data record.
 */
int MediaDataHelper::Insert(Uri &uri, const NativeRdb::ValuesBucket &value)
{
    HILOG_INFO("MediaDataHelper::Insert start.");
    int index = INVALID_VALUE;
    if (!CheckUriParam(uri)) {
        HILOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return index;
    }

    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::Insert before ConnectMediaDataExtAbility.");
        if (!mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->ConnectMediaDataExtAbility(want_, token_);
        }
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
        HILOG_INFO("MediaDataHelper::Insert after ConnectMediaDataExtAbility.");
        if (isSystemCaller_ && mediaDataProxy_) {
            AddMediaDataDeathRecipient(mediaDataProxy_->AsObject());
        }
    } else {
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
    }

    if (mediaDataProxy_ == nullptr) {
        HILOG_ERROR("%{public}s failed with invalid mediaDataProxy_", __func__);
        return index;
    }

    HILOG_INFO("MediaDataHelper::Insert before mediaDataProxy_->Insert.");
    index = mediaDataProxy_->Insert(uri, value);
    HILOG_INFO("MediaDataHelper::Insert after mediaDataProxy_->Insert.");
    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::Insert before DisconnectMediaDataExtAbility.");
        if (mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->DisconnectMediaDataExtAbility();
        }
        HILOG_INFO("MediaDataHelper::Insert after DisconnectMediaDataExtAbility.");
        mediaDataProxy_ = nullptr;
    }
    HILOG_INFO("MediaDataHelper::Insert end.");
    return index;
}

/**
 * @brief Updates data records in the database.
 *
 * @param uri Indicates the path of data to update.
 * @param value Indicates the data to update. This parameter can be null.
 * @param predicates Indicates filter criteria. You should define the processing logic when this parameter is null.
 *
 * @return Returns the number of data records updated.
 */
int MediaDataHelper::Update(
    Uri &uri, const NativeRdb::ValuesBucket &value, const NativeRdb::DataAbilityPredicates &predicates)
{
    HILOG_INFO("MediaDataHelper::Update start.");
    int index = INVALID_VALUE;
    if (!CheckUriParam(uri)) {
        HILOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return index;
    }

    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::Update before ConnectMediaDataExtAbility.");
        if (!mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->ConnectMediaDataExtAbility(want_, token_);
        }
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
        HILOG_INFO("MediaDataHelper::Update after ConnectMediaDataExtAbility.");
        if (isSystemCaller_ && mediaDataProxy_) {
            AddMediaDataDeathRecipient(mediaDataProxy_->AsObject());
        }
    } else {
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
    }

    if (mediaDataProxy_ == nullptr) {
        HILOG_ERROR("%{public}s failed with invalid mediaDataProxy_", __func__);
        return index;
    }

    HILOG_INFO("MediaDataHelper::Update before mediaDataProxy_->Update.");
    index = mediaDataProxy_->Update(uri, value, predicates);
    HILOG_INFO("MediaDataHelper::Update after mediaDataProxy_->Update.");
    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::Update before DisconnectMediaDataExtAbility.");
        if (mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->DisconnectMediaDataExtAbility();
        }
        HILOG_INFO("MediaDataHelper::Update after DisconnectMediaDataExtAbility.");
        mediaDataProxy_ = nullptr;
    }
    HILOG_INFO("MediaDataHelper::Update end.");
    return index;
}

/**
 * @brief Deletes one or more data records from the database.
 *
 * @param uri Indicates the path of the data to operate.
 * @param predicates Indicates filter criteria. You should define the processing logic when this parameter is null.
 *
 * @return Returns the number of data records deleted.
 */
int MediaDataHelper::Delete(Uri &uri, const NativeRdb::DataAbilityPredicates &predicates)
{
    HILOG_INFO("MediaDataHelper::Delete start.");
    int index = INVALID_VALUE;
    if (!CheckUriParam(uri)) {
        HILOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return index;
    }

    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::Delete before ConnectMediaDataExtAbility.");
        if (!mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->ConnectMediaDataExtAbility(want_, token_);
        }
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
        HILOG_INFO("MediaDataHelper::Delete after ConnectMediaDataExtAbility.");
        if (isSystemCaller_ && mediaDataProxy_) {
            AddMediaDataDeathRecipient(mediaDataProxy_->AsObject());
        }
    } else {
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
    }

    if (mediaDataProxy_ == nullptr) {
        HILOG_ERROR("%{public}s failed with invalid mediaDataProxy_", __func__);
        return index;
    }

    HILOG_INFO("MediaDataHelper::Delete before mediaDataProxy_->Delete.");
    index = mediaDataProxy_->Delete(uri, predicates);
    HILOG_INFO("MediaDataHelper::Delete after mediaDataProxy_->Delete.");
    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::Delete before DisconnectMediaDataExtAbility.");
        if (mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->DisconnectMediaDataExtAbility();
        }
        HILOG_INFO("MediaDataHelper::Delete after DisconnectMediaDataExtAbility.");
        mediaDataProxy_ = nullptr;
    }
    HILOG_INFO("MediaDataHelper::Delete end.");
    return index;
}

/**
 * @brief Deletes one or more data records from the database.
 *
 * @param uri Indicates the path of data to query.
 * @param columns Indicates the columns to query. If this parameter is null, all columns are queried.
 * @param predicates Indicates filter criteria. You should define the processing logic when this parameter is null.
 *
 * @return Returns the query result.
 */
std::shared_ptr<NativeRdb::AbsSharedResultSet> MediaDataHelper::Query(
    Uri &uri, std::vector<std::string> &columns, const NativeRdb::DataAbilityPredicates &predicates)
{
    HILOG_INFO("MediaDataHelper::Query start.");
    std::shared_ptr<NativeRdb::AbsSharedResultSet> resultset = nullptr;
/*
    if (!CheckUriParam(uri)) {
        HILOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return resultset;
    }
*/

    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::Query before ConnectMediaDataExtAbility.");
        if (!mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->ConnectMediaDataExtAbility(want_, token_);
        }
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
        HILOG_INFO("MediaDataHelper::Query after ConnectMediaDataExtAbility.");
        if (isSystemCaller_ && mediaDataProxy_) {
            AddMediaDataDeathRecipient(mediaDataProxy_->AsObject());
        }
    } else {
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
    }

    if (mediaDataProxy_ == nullptr) {
        HILOG_ERROR("%{public}s failed with invalid mediaDataProxy_", __func__);
        return resultset;
    }

    HILOG_INFO("MediaDataHelper::Query before mediaDataProxy_->Query.");
    resultset = mediaDataProxy_->Query(uri, columns, predicates);
    HILOG_INFO("MediaDataHelper::Query after mediaDataProxy_->Query.");
    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::Query before DisconnectMediaDataExtAbility.");
        if (mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->DisconnectMediaDataExtAbility();
        }
        HILOG_INFO("MediaDataHelper::Query after DisconnectMediaDataExtAbility.");
        mediaDataProxy_ = nullptr;
    }
    HILOG_INFO("MediaDataHelper::Query end.");
    return resultset;
}

/**
 * @brief Obtains the MIME type matching the data specified by the URI of the data share. This method should be
 * implemented by a data share. Data abilities supports general data types, including text, HTML, and JPEG.
 *
 * @param uri Indicates the URI of the data.
 *
 * @return Returns the MIME type that matches the data specified by uri.
 */
std::string MediaDataHelper::GetType(Uri &uri)
{
    HILOG_INFO("MediaDataHelper::GetType start.");
    std::string type;
    if (!CheckUriParam(uri)) {
        HILOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return type;
    }

    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::GetType before ConnectMediaDataExtAbility.");
        if (!mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->ConnectMediaDataExtAbility(want_, token_);
        }
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
        HILOG_INFO("MediaDataHelper::GetType after ConnectMediaDataExtAbility.");
        if (isSystemCaller_ && mediaDataProxy_) {
            AddMediaDataDeathRecipient(mediaDataProxy_->AsObject());
        }
    } else {
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
    }

    if (mediaDataProxy_ == nullptr) {
        HILOG_ERROR("%{public}s failed with invalid mediaDataProxy_", __func__);
        return type;
    }

    HILOG_INFO("MediaDataHelper::GetType before mediaDataProxy_->GetType.");
    type = mediaDataProxy_->GetType(uri);
    HILOG_INFO("MediaDataHelper::GetType after mediaDataProxy_->GetType.");
    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::GetType before DisconnectMediaDataExtAbility.");
        if (mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->DisconnectMediaDataExtAbility();
        }
        HILOG_INFO("MediaDataHelper::GetType after DisconnectMediaDataExtAbility.");
        mediaDataProxy_ = nullptr;
    }
    HILOG_INFO("MediaDataHelper::GetType end.");
    return type;
}

/**
 * @brief Inserts multiple data records into the database.
 *
 * @param uri Indicates the path of the data to operate.
 * @param values Indicates the data records to insert.
 *
 * @return Returns the number of data records inserted.
 */
int MediaDataHelper::BatchInsert(Uri &uri, const std::vector<NativeRdb::ValuesBucket> &values)
{
    HILOG_INFO("MediaDataHelper::BatchInsert start.");
    int ret = INVALID_VALUE;
    if (!CheckUriParam(uri)) {
        HILOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return ret;
    }

    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::BatchInsert before ConnectMediaDataExtAbility.");
        if (!mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->ConnectMediaDataExtAbility(want_, token_);
        }
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
        HILOG_INFO("MediaDataHelper::BatchInsert after ConnectMediaDataExtAbility.");
        if (isSystemCaller_ && mediaDataProxy_) {
            AddMediaDataDeathRecipient(mediaDataProxy_->AsObject());
        }
    } else {
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
    }

    if (mediaDataProxy_ == nullptr) {
        HILOG_ERROR("%{public}s failed with invalid mediaDataProxy_", __func__);
        return ret;
    }

    HILOG_INFO("MediaDataHelper::BatchInsert before mediaDataProxy_->BatchInsert.");
    ret = mediaDataProxy_->BatchInsert(uri, values);
    HILOG_INFO("MediaDataHelper::BatchInsert after mediaDataProxy_->BatchInsert.");
    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::BatchInsert before DisconnectMediaDataExtAbility.");
        if (mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->DisconnectMediaDataExtAbility();
        }
        HILOG_INFO("MediaDataHelper::BatchInsert after DisconnectMediaDataExtAbility.");
        mediaDataProxy_ = nullptr;
    }
    HILOG_INFO("MediaDataHelper::BatchInsert end.");
    return ret;
}

bool MediaDataHelper::CheckUriParam(const Uri &uri)
{
/*
    HILOG_INFO("MediaDataHelper::CheckUriParam start.");
    Uri checkUri(uri.ToString());
    if (!CheckOhosUri(checkUri)) {
        HILOG_ERROR("MediaDataHelper::CheckUriParam failed. CheckOhosUri uri failed");
        return false;
    }

    if (uri_ != nullptr) {
        if (!CheckOhosUri(*uri_)) {
            HILOG_ERROR("MediaDataHelper::CheckUriParam failed. CheckOhosUri uri_ failed");
            return false;
        }

        std::vector<std::string> checkSegments;
        checkUri.GetPathSegments(checkSegments);

        std::vector<std::string> segments;
        uri_->GetPathSegments(segments);

        if (checkSegments[0] != segments[0]) {
            HILOG_ERROR("MediaDataHelper::CheckUriParam failed. the mediadata in uri doesn't equal the one in uri_.");
            return false;
        }
    }
    HILOG_INFO("MediaDataHelper::CheckUriParam end.");
    */
    return true;
}

bool MediaDataHelper::CheckOhosUri(const Uri &uri)
{
    HILOG_INFO("MediaDataHelper::CheckOhosUri start.");
    Uri checkUri(uri.ToString());
    if (checkUri.GetScheme() != SCHEME_MEDIADATA) {
        HILOG_ERROR("MediaDataHelper::CheckOhosUri failed. uri is not a mediadata one.");
        return false;
    }

    std::vector<std::string> segments;
    checkUri.GetPathSegments(segments);
    if (segments.empty()) {
        HILOG_ERROR("MediaDataHelper::CheckOhosUri failed. There is no segments in the uri.");
        return false;
    }

    if (checkUri.GetPath() == "") {
        HILOG_ERROR("MediaDataHelper::CheckOhosUri failed. The path in the uri is empty.");
        return false;
    }
    HILOG_INFO("MediaDataHelper::CheckOhosUri end.");
    return true;
}

/**
 * @brief Registers an observer to DataObsMgr specified by the given Uri.
 *
 * @param uri, Indicates the path of the data to operate.
 * @param dataObserver, Indicates the IDataAbilityObserver object.
 */
void MediaDataHelper::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    HILOG_INFO("MediaDataHelper::RegisterObserver start.");
    if (!CheckUriParam(uri)) {
        HILOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return;
    }

    if (dataObserver == nullptr) {
        HILOG_ERROR("%{public}s called. dataObserver is nullptr", __func__);
        return;
    }
    /*

    Uri tmpUri(uri.ToString());
    std::lock_guard<std::mutex> lock_l(oplock_);
    if (uri_ == nullptr) {
        auto mediadata = registerMap_.find(dataObserver);
        if (mediadata == registerMap_.end()) {
            if (!mediaDataConnection_->IsExtAbilityConnected()) {
                mediaDataConnection_->ConnectMediaDataExtAbility(want_, token_);
            }
            mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
            registerMap_.emplace(dataObserver, mediaDataProxy_);
            uriMap_.emplace(dataObserver, tmpUri.GetPath());
        } else {
            auto path = uriMap_.find(dataObserver);
            if (path->second != tmpUri.GetPath()) {
                HILOG_ERROR("MediaDataHelper::RegisterObserver failed input uri's path is not equal the one the "
                         "observer used");
                return;
            }
            mediaDataProxy_ = mediadata->second;
        }
    } else {
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
    }

    if (mediaDataProxy_ == nullptr) {
        HILOG_ERROR("MediaDataHelper::RegisterObserver failed mediaDataProxy_ == nullptr");
        registerMap_.erase(dataObserver);
        uriMap_.erase(dataObserver);
        return;
    }
    mediaDataProxy_->RegisterObserver(uri, dataObserver);
    */
    HILOG_INFO("MediaDataHelper::RegisterObserver end.");
}

/**
 * @brief Deregisters an observer used for DataObsMgr specified by the given Uri.
 *
 * @param uri, Indicates the path of the data to operate.
 * @param dataObserver, Indicates the IDataAbilityObserver object.
 */
void MediaDataHelper::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    HILOG_INFO("MediaDataHelper::UnregisterObserver start.");
    if (!CheckUriParam(uri)) {
        HILOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return;
    }

    if (dataObserver == nullptr) {
        HILOG_ERROR("%{public}s called. dataObserver is nullptr", __func__);
        return;
    }

    Uri tmpUri(uri.ToString());
    std::lock_guard<std::mutex> lock_l(oplock_);
    if (uri_ == nullptr) {
        auto mediadata = registerMap_.find(dataObserver);
        if (mediadata == registerMap_.end()) {
            return;
        }
        auto path = uriMap_.find(dataObserver);
        if (path->second != tmpUri.GetPath()) {
            HILOG_ERROR("MediaDataHelper::UnregisterObserver failed input uri's path is not equal the one the "
                     "observer used");
            return;
        }
        mediaDataProxy_ = mediadata->second;
    } else {
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
    }

    if (mediaDataProxy_ == nullptr) {
        HILOG_ERROR("MediaDataHelper::UnregisterObserver failed mediaDataProxy_ == nullptr");
        return;
    }

    mediaDataProxy_->UnregisterObserver(uri, dataObserver);
    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::UnregisterObserver before DisconnectMediaDataExtAbility.");
        if (mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->DisconnectMediaDataExtAbility();
        }
        HILOG_INFO("MediaDataHelper::UnregisterObserver after DisconnectMediaDataExtAbility.");
        mediaDataProxy_ = nullptr;
    }
    registerMap_.erase(dataObserver);
    uriMap_.erase(dataObserver);
    HILOG_INFO("MediaDataHelper::UnregisterObserver end.");
}

/**
 * @brief Notifies the registered observers of a change to the data resource specified by Uri.
 *
 * @param uri, Indicates the path of the data to operate.
 */
void MediaDataHelper::NotifyChange(const Uri &uri)
{
    HILOG_INFO("MediaDataHelper::NotifyChange start.");
    if (!CheckUriParam(uri)) {
        HILOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return;
    }

    if (mediaDataProxy_ == nullptr) {
        if (!mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->ConnectMediaDataExtAbility(want_, token_);
        }
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
    } else {
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
    }

    if (mediaDataProxy_ == nullptr) {
        HILOG_ERROR("%{public}s failed with invalid mediaDataProxy_", __func__);
        return;
    }

    mediaDataProxy_->NotifyChange(uri);

    if (uri_ == nullptr) {
        if (mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->DisconnectMediaDataExtAbility();
        }
        mediaDataProxy_ = nullptr;
    }
    HILOG_INFO("MediaDataHelper::NotifyChange end.");
}

/**
 * @brief Converts the given uri that refer to the data share into a normalized URI. A normalized URI can be used
 * across devices, persisted, backed up, and restored. It can refer to the same item in the data share even if the
 * context has changed. If you implement URI normalization for a data share, you must also implement
 * denormalizeUri(ohos.utils.net.Uri) to enable URI denormalization. After this feature is enabled, URIs passed to any
 * method that is called on the data share must require normalization verification and denormalization. The default
 * implementation of this method returns null, indicating that this data share does not support URI normalization.
 *
 * @param uri Indicates the Uri object to normalize.
 *
 * @return Returns the normalized Uri object if the data share supports URI normalization; returns null otherwise.
 */
Uri MediaDataHelper::NormalizeUri(Uri &uri)
{
    HILOG_INFO("MediaDataHelper::NormalizeUri start.");
    Uri urivalue("");
    if (!CheckUriParam(uri)) {
        HILOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return urivalue;
    }

    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::NormalizeUri before ConnectMediaDataExtAbility.");
        if (!mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->ConnectMediaDataExtAbility(want_, token_);
        }
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
        HILOG_INFO("MediaDataHelper::NormalizeUri after ConnectMediaDataExtAbility.");
        if (isSystemCaller_ && mediaDataProxy_) {
            AddMediaDataDeathRecipient(mediaDataProxy_->AsObject());
        }
    } else {
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
    }

    if (mediaDataProxy_ == nullptr) {
        HILOG_ERROR("%{public}s failed with invalid mediaDataProxy_", __func__);
        return urivalue;
    }

    HILOG_INFO("MediaDataHelper::NormalizeUri before mediaDataProxy_->NormalizeUri.");
    urivalue = mediaDataProxy_->NormalizeUri(uri);
    HILOG_INFO("MediaDataHelper::NormalizeUri after mediaDataProxy_->NormalizeUri.");
    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::NormalizeUri before DisconnectMediaDataExtAbility.");
        if (mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->DisconnectMediaDataExtAbility();
        }
        HILOG_INFO("MediaDataHelper::NormalizeUri after DisconnectMediaDataExtAbility.");
        mediaDataProxy_ = nullptr;
    }
    HILOG_INFO("MediaDataHelper::NormalizeUri end.");
    return urivalue;
}

/**
 * @brief Converts the given normalized uri generated by normalizeUri(ohos.utils.net.Uri) into a denormalized one.
 * The default implementation of this method returns the original URI passed to it.
 *
 * @param uri uri Indicates the Uri object to denormalize.
 *
 * @return Returns the denormalized Uri object if the denormalization is successful; returns the original Uri passed to
 * this method if there is nothing to do; returns null if the data identified by the original Uri cannot be found in
 * the current environment.
 */
Uri MediaDataHelper::DenormalizeUri(Uri &uri)
{
    HILOG_INFO("MediaDataHelper::DenormalizeUri start.");
    Uri urivalue("");
    if (!CheckUriParam(uri)) {
        HILOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return urivalue;
    }

    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::DenormalizeUri before ConnectMediaDataExtAbility.");
        if (!mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->ConnectMediaDataExtAbility(want_, token_);
        }
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
        HILOG_INFO("MediaDataHelper::DenormalizeUri after ConnectMediaDataExtAbility.");
        if (isSystemCaller_ && mediaDataProxy_) {
            AddMediaDataDeathRecipient(mediaDataProxy_->AsObject());
        }
    } else {
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
    }

    if (mediaDataProxy_ == nullptr) {
        HILOG_ERROR("%{public}s failed with invalid mediaDataProxy_", __func__);
        return urivalue;
    }

    HILOG_INFO("MediaDataHelper::DenormalizeUri before mediaDataProxy_->DenormalizeUri.");
    urivalue = mediaDataProxy_->DenormalizeUri(uri);
    HILOG_INFO("MediaDataHelper::DenormalizeUri after mediaDataProxy_->DenormalizeUri.");
    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::DenormalizeUri before DisconnectMediaDataExtAbility.");
        if (mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->DisconnectMediaDataExtAbility();
        }
        HILOG_INFO("MediaDataHelper::DenormalizeUri after DisconnectMediaDataExtAbility.");
        mediaDataProxy_ = nullptr;
    }
    HILOG_INFO("MediaDataHelper::DenormalizeUri end.");
    return urivalue;
}

void MediaDataDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    HILOG_INFO("recv MediaDataDeathRecipient death notice");
    if (handler_) {
        handler_(remote);
    }
    HILOG_INFO("MediaDataHelper::OnRemoteDied end.");
}

MediaDataDeathRecipient::MediaDataDeathRecipient(RemoteDiedHandler handler) : handler_(handler)
{}

MediaDataDeathRecipient::~MediaDataDeathRecipient()
{}

std::vector<std::shared_ptr<DataAbilityResult>> MediaDataHelper::ExecuteBatch(
    const Uri &uri, const std::vector<std::shared_ptr<DataAbilityOperation>> &operations)
{
    HILOG_INFO("MediaDataHelper::ExecuteBatch start");
    std::vector<std::shared_ptr<DataAbilityResult>> results;
    if (!CheckUriParam(uri)) {
        HILOG_ERROR("MediaDataHelper::ExecuteBatch. CheckUriParam uri failed");
        return results;
    }
    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::ExecuteBatch before ConnectMediaDataExtAbility.");
        if (!mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->ConnectMediaDataExtAbility(want_, token_);
        }
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
        HILOG_INFO("MediaDataHelper::ExecuteBatch after ConnectMediaDataExtAbility.");
        if (mediaDataProxy_ == nullptr) {
            HILOG_ERROR("MediaDataHelper::ExecuteBatch failed mediaDataProxy_ == nullptr");
            return results;
        }
    } else {
        mediaDataProxy_ = mediaDataConnection_->GetMediaDataProxy();
    }

    if (mediaDataProxy_ == nullptr) {
        HILOG_ERROR("%{public}s failed with invalid mediaDataProxy_", __func__);
        return results;
    }

    HILOG_INFO("MediaDataHelper::ExecuteBatch before mediaDataProxy_->ExecuteBatch.");
    results = mediaDataProxy_->ExecuteBatch(operations);
    HILOG_INFO("MediaDataHelper::ExecuteBatch after mediaDataProxy_->ExecuteBatch.");
    if (uri_ == nullptr) {
        HILOG_INFO("MediaDataHelper::ExecuteBatch before DisconnectMediaDataExtAbility.");
        if (mediaDataConnection_->IsExtAbilityConnected()) {
            mediaDataConnection_->DisconnectMediaDataExtAbility();
        }
        HILOG_INFO("MediaDataHelper::ExecuteBatch after DisconnectMediaDataExtAbility.");
        mediaDataProxy_ = nullptr;
    }
    HILOG_INFO("MediaDataHelper::ExecuteBatch end");
    return results;
}
}  // namespace AppExecFwk
}  // namespace OHOS
