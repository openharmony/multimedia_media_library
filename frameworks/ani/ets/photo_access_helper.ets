/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

import { Context, MediaChangeRequest, FetchOptions, ChangeData } from "./media_library_common.ets";
import { PhotoType, AlbumType, AlbumSubtype, NotifyType } from "./media_library_enum.ets";

class FetchResult<T> {
}

class Album {
}

class PhotoAsset {
    static { loadLibrary("photo_access_helper_ani"); }

    private  nativePhotoAssetImpl:long = 0;
  
    constructor(context: long) {
        if (this.nativePhotoAssetImpl == 0) {
            this.nativePhotoAssetImpl = context;
        }
    }

    hu(): void {
    }
}

class PhotoCreateOptions {
}

class CreateOptions {
}

class ChangeDataInner implements ChangeData {
    type: NotifyType = NotifyType.NOTIFY_ADD;
    uris: Array<string> = new Array<string>();
    extraUris: Array<string> = new Array<string>();
}

export class PhotoAccessHelperError<T = string> {
    code: int; // error code
    data: T; // error data
    constructor(code: int, data: T) {
        this.code = code;
        this.data = data;
    }
}

class Result<T, E> {
    result: T; // seccess, result data
    error: E; // failed, error data
    constructor(result: T, error: E) {
        this.result = result;
        this.error = error;
    }
}

type AsyncCallback<T, E = void> = (err: PhotoAccessHelperError<E>, data: T) => void;

export interface PhotoAccessHelper {
}

export class PhotoAccessHelperHandle implements PhotoAccessHelper {
    static { loadLibrary("photo_access_helper_ani"); }
    private nativePhotoAccessHelper:long = 0;

    constructor(context: long) {
        if (this.nativePhotoAccessHelper == 0) {
             this.nativePhotoAccessHelper = context;
        }
    }

    native static applyChanges(mediaChangeRequest: MediaChangeRequest): void;
    native static release(): void;
    native getAlbums(type: AlbumType, subtype: AlbumSubtype, options?: FetchOptions): FetchResult<Album>;
    //native static getAssets(options: FetchOptions): FetchResult<PhotoAsset>;
    native static getBurstAssets(burstKey: string, options: FetchOptions): FetchResult<PhotoAsset>;
    native static createAsset(displayName: string, options: PhotoCreateOptions): PhotoAsset;
    native static createAsset(photoType: PhotoType, extension: string, options: CreateOptions): string;
    native static createAsset(photoType: PhotoType, extension: string, options?: CreateOptions): string;
    native static registerChange(uri: string, forChildUris: boolean): ChangeData;
    native static unRegisterChange(uri: string): ChangeData;
    private native createAsset1(displayName: string): Result<PhotoAsset, PhotoAccessHelperError>;
    private native gettid(): int;

    native getAssetsSync(options: FetchOptions): Array<PhotoAsset>;
    private native getAssetsInner(options: FetchOptions): FetchResult<PhotoAsset>;
    getAssets(options: FetchOptions): Promise<FetchResult<PhotoAsset>> {
        let p = new Promise<FetchResult<PhotoAsset>>((resolve: (v: FetchResult<PhotoAsset>) => void, reject: (error: BusinessError) => void) => {
            let cb = (): undefined => {
                this.getAssetsInner(options);
                return undefined;
            }

            let p1 = taskpool.execute(cb);
            p1.then((e :NullishType) => {
                let r =  e as Result<FetchResult<PhotoAsset>, BusinessError>;
                let err = r.error;
                if(err.code != 0){
                    reject(err);
                }
                else{
                    resolve(r.result);
                }
            });
        });
        return p;
    }
}

export native function getPhotoAccessHelper(context: Context): PhotoAccessHelper;
