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

const photoAccessHelper = requireInternal('file.photoAccessHelper');
const bundleManager = requireNapi('bundle.bundleManager');

const ARGS_TWO = 2;

const WRITE_PERMISSION = 'ohos.permission.WRITE_IMAGEVIDEO';

const PERMISSION_DENIED = 13900012;
const ERR_CODE_PARAMERTER_INVALID = 13900020;
const ERROR_MSG_WRITE_PERMISSION = 'not have ohos.permission.WRITE_IMAGEVIDEO';
const ERROR_MSG_USER_DENY = 'user deny';
const ERROR_MSG_PARAMERTER_INVALID = 'input parmaeter invalid';

const MAX_DELETE_NUMBER = 3600;
const MIN_DELETE_NUMBER = 1;

let gContext = undefined;

class BusinessError extends Error {
  constructor(msg, code) {
    super(msg);
    this.code = code || PERMISSION_DENIED;
  }
}
function checkParams(uriList, asyncCallback) {
  if (arguments.length > ARGS_TWO) {
    return false;
  }
  if (!Array.isArray(uriList)) {
    return false;
  }
  if (asyncCallback && typeof asyncCallback !== 'function') {
    return false;
  }
  if (uriList.length < MIN_DELETE_NUMBER || uriList.length > MAX_DELETE_NUMBER) {
    return false;
  }
  return true;
}
function errorResult(rej, asyncCallback) {
  if (asyncCallback) {
    return asyncCallback(rej);
  }
  return new Promise((resolve, reject) => {
    reject(rej);
  });
}

async function createPhotoDeleteRequestParamsOk(uriList, asyncCallback) {
  let flags = bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION;
  let { reqPermissionDetails } = await bundleManager.getBundleInfoForSelf(flags);
  let isPermission = reqPermissionDetails.findIndex(({ name }) => name === WRITE_PERMISSION) !== -1;
  if (!isPermission) {
    return errorResult(new BusinessError(ERROR_MSG_WRITE_PERMISSION), asyncCallback);
  }
  const startParameter = {
    action: 'ohos.want.action.deleteDialog',
    parameters: {
      uris: uriList,
    },
  };
  try {
    const result = await gContext.requestDialogService(startParameter);
    if (result === null || result === undefined) {
      console.log('photoAccessHelper createDeleteRequest return null');
      return errorResult(Error('requestDialog return undefined'), asyncCallback);
    }
    if (asyncCallback) {
      if (result.result === 0) {
        return asyncCallback();
      } else {
        return asyncCallback(new BusinessError(ERROR_MSG_USER_DENY));
      }
    }
    return new Promise((resolve, reject) => {
      if (result.result === 0) {
        resolve();
      } else {
        reject(new BusinessError(ERROR_MSG_USER_DENY));
      }
    });
  } catch (error) {
    return errorResult(new BusinessError(error.message, error.code), asyncCallback);
  }
}

function createDeleteRequest(...params) {
  if (!checkParams(...params)) {
    throw new BusinessError(ERROR_MSG_PARAMERTER_INVALID, ERR_CODE_PARAMERTER_INVALID);
  }
  return createPhotoDeleteRequestParamsOk(...params);
}

function getPhotoAccessHelper(context) {
  if (context === undefined) {
    console.log('photoAccessHelper gContext undefined');
    throw Error('photoAccessHelper gContext undefined');
  }
  gContext = context;
  let helper = photoAccessHelper.getPhotoAccessHelper(gContext);
  if (helper !== undefined) {
    console.log('photoAccessHelper getPhotoAccessHelper inner add createDeleteRequest');
    helper.createDeleteRequest = createDeleteRequest;
  }
  return helper;
}

function getPhotoAccessHelperAsync(context, asyncCallback) {
  if (context === undefined) {
    console.log('photoAccessHelper gContext undefined');
    throw Error('photoAccessHelper gContext undefined');
  }
  gContext = context;
  if (arguments.length === 1) {
    return photoAccessHelper.getPhotoAccessHelperAsync(gContext)
      .then((helper) => {
        if (helper !== undefined) {
          console.log('photoAccessHelper getPhotoAccessHelperAsync inner add createDeleteRequest');
          helper.createDeleteRequest = createDeleteRequest;
        }
        return helper;
      })
      .catch((err) => {
        console.log('photoAccessHelper getPhotoAccessHelperAsync err ' + err);
        throw Error(err);
      });
  } else if (arguments.length === ARGS_TWO && typeof asyncCallback === 'function') {
    photoAccessHelper.getPhotoAccessHelperAsync(gContext, (err, helper) => {
      console.log('photoAccessHelper getPhotoAccessHelperAsync callback ' + err);
      if (err) {
        asyncCallback(err);
      } else {
        if (helper !== undefined) {
          console.log('photoAccessHelper getPhotoAccessHelperAsync callback add createDeleteRequest');
          helper.createDeleteRequest = createDeleteRequest;
        }
        asyncCallback(err, helper);
      }
    });
  } else {
    console.log('photoAccessHelper getPhotoAccessHelperAsync param invalid');
    throw new BusinessError(ERROR_MSG_PARAMERTER_INVALID, ERR_CODE_PARAMERTER_INVALID);
  }
  return undefined;
}

export default {
  getPhotoAccessHelper,
  getPhotoAccessHelperAsync,
  PhotoType: photoAccessHelper.PhotoType,
  PhotoKeys: photoAccessHelper.PhotoKeys,
  AlbumKeys: photoAccessHelper.AlbumKeys,
  AlbumType: photoAccessHelper.AlbumType,
  AlbumSubtype: photoAccessHelper.AlbumSubtype,
  PositionType: photoAccessHelper.PositionType,
  PhotoSubtype: photoAccessHelper.PhotoSubtype,
  NotifyType: photoAccessHelper.NotifyType,
  DefaultChangeUri: photoAccessHelper.DefaultChangeUri,
};
