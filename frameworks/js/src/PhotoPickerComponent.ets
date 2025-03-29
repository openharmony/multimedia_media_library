/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

import photoAccessHelper from '@ohos.file.photoAccessHelper';
import { fileIo as fs, fileUri } from '@kit.CoreFileKit';
import { AsyncCallback, BusinessError } from '@kit.BasicServicesKit';
import { bundleManager } from '@kit.AbilityKit';

const PHOTO_VIEW_MIME_TYPE_MAP = new Map([
    ['*/*', 'FILTER_MEDIA_TYPE_ALL'],
    ['image/*', 'FILTER_MEDIA_TYPE_IMAGE'],
    ['video/*', 'FILTER_MEDIA_TYPE_VIDEO'],
    ['image/movingPhoto', 'FILTER_MEDIA_TYPE_IMAGE_MOVING_PHOTO']
])

interface MimeTypeFilter {
  MimeTypeArray: string[],
  filterType: number
}

@Component
export struct PhotoPickerComponent {
  pickerOptions?: PickerOptions | undefined;
  onSelect?: (uri: string) => void;
  onDeselect?: (uri: string) => void;
  onItemClicked?: (itemInfo: ItemInfo, clickType: ClickType) => boolean;
  onEnterPhotoBrowser?: (photoBrowserInfo: PhotoBrowserInfo) => boolean;
  onExitPhotoBrowser?: (photoBrowserInfo: PhotoBrowserInfo) => boolean;
  onPickerControllerReady?: () => void;
  onPhotoBrowserChanged?: (browserItemInfo: BaseItemInfo) => boolean;
  onSelectedItemsDeleted?: ItemsDeletedCallback;
  onExceedMaxSelected?: ExceedMaxSelectedCallback;
  onCurrentAlbumDeleted?: CurrentAlbumDeletedCallback;
  onVideoPlayStateChanged?: VideoPlayStateChangedCallback;
  @ObjectLink @Watch('onChanged') pickerController: PickerController;
  private proxy: UIExtensionProxy | undefined;
  @State revokeIndex = 0;

  private onChanged(): void {
    if (!this.proxy) {
      return;
    }
    let data = this.pickerController?.data;
    if (data?.has('SET_SELECTED_URIS')) {
      this.proxy.send({ 'selectUris': data?.get('SET_SELECTED_URIS') as Array<string> });
      console.info('PhotoPickerComponent onChanged: SET_SELECTED_URIS');
    } else if (data?.has('SET_ALBUM_URI')) {
      this.proxy.send({ 'albumUri': data?.get('SET_ALBUM_URI') as string });
      console.info('PhotoPickerComponent onChanged: SET_ALBUM_URI');
    } else if (data?.has('SET_MAX_SELECT_COUNT')) {
      this.onSetMaxSelectCount(data);
    } else if (data?.has('SET_PHOTO_BROWSER_ITEM')) {
      this.onSetPhotoBrowserItem(data);
    } else {
      this.otherOnChange(data);
    }
  }

  private otherOnChange(data?: Map<string, Object>) {
    if (data?.has('EXIT_PHOTO_BROWSER')) {
      this.handleExitPhotoBrowser();
    } else if (data?.has('SET_PHOTO_BROWSER_UI_ELEMENT_VISIBILITY')) {
      this.onSetPhotoBrowserUIElementVisibility(data);
    } else if (data?.has('CREATE_URI')) {
      this.onCreateUri(data);
      console.info('PhotoPickerComponent onChanged: CREATE_URI');
    } else if (data?.has('REPLACE_URI')) {
      this.onReplaceUri(data);
      console.info('PhotoPickerComponent onChanged: REPLACE_URI');
    } else if (data?.has('SAVE_TRUSTED_PHOTO_ASSETS')) {
      this.onSaveTrustedPhotoAssets(data);
      console.info('PhotoPickerComponent onChanged: SAVE_REPLACE_PHOTO_ASSETS');
    } else {
      console.info('PhotoPickerComponent onChanged: other case');
    }
  }

  private onSetMaxSelectCount(data?: Map<string, Object>): void {
    let maxSelected: MaxSelected = data?.get('SET_MAX_SELECT_COUNT') as MaxSelected;
    let map: Map<MaxCountType, number> | undefined = maxSelected?.data;
    this.proxy.send({
      'totalCount': map?.get(MaxCountType.TOTAL_MAX_COUNT),
      'photoCount': map?.get(MaxCountType.PHOTO_MAX_COUNT),
      'videoCount': map?.get(MaxCountType.VIDEO_MAX_COUNT)
    });
    console.info('PhotoPickerComponent onChanged: SET_MAX_SELECT_COUNT');
  }

  private onSetPhotoBrowserItem(data?: Map<string, Object>): void {
    let photoBrowserRangeInfo: PhotoBrowserRangeInfo = data?.get('SET_PHOTO_BROWSER_ITEM') as PhotoBrowserRangeInfo;
    this.proxy?.send({
      'itemUri': photoBrowserRangeInfo?.uri,
      'photoBrowserRange': photoBrowserRangeInfo?.photoBrowserRange
    });
    console.info('PhotoPickerComponent onChanged: SET_PHOTO_BROWSER_ITEM');
  }

  private handleExitPhotoBrowser(): void {
    this.proxy.send({ 'exitPhotoBrowser': true });
    console.info('PhotoPickerComponent onChanged: EXIT_PHOTO_BROWSER');
  }

  private onSetPhotoBrowserUIElementVisibility(data?: Map<string, Object>): void {
    let photoBrowserUIElementVisibility: PhotoBrowserUIElementVisibility =
      data?.get('SET_PHOTO_BROWSER_UI_ELEMENT_VISIBILITY') as PhotoBrowserUIElementVisibility;
    this.proxy?.send({
      'elements': photoBrowserUIElementVisibility?.elements,
      'isVisible': photoBrowserUIElementVisibility?.isVisible
    });
    console.info('PhotoPickerComponent onChanged: SET_PHOTO_BROWSER_UI_ELEMENT_VISIBILITY');
  }

  private onCreateUri(data?: Map<string, Object>): void {
    let array = data?.get('CREATE_URI') as Array<Object>;
    this.proxy?.send({
      selectedMediaUri: array[0],
      createUri: array[1],
      date: array[2]
    });
    console.info('PhotoPickerComponent onChanged CREATE_URI');
  }

  private onReplaceUri(data?: Map<string, Object>): void {
    let array = data?.get('REPLACE_URI') as Array<Object>;
    this.proxy?.send({
      oriUri: array[0],
      replaceUri: array[1],
      date: array[2]
    });
    console.info('PhotoPickerComponent onChanged REPLACE_URI');
  }

  private onSaveTrustedPhotoAssets(data?: Map<string, Object>): void {
    let array: Array<object> = data?.get('SAVE_TRUSTED_PHOTO_ASSETS') as Array<object>;
    this.proxy?.send({
      replaceUris: array[0],
      config: array[1],
      saveMode: array[2],
      appName: array[3],
      date: array[4]
    });
    console.info('PhotoPickerComponent onChanged SAVE_REPLACE_PHOTO_ASSETS');
  }

  build() {
    Row() {
      Column() {
        SecurityUIExtensionComponent({
          parameters: {
            errorRevokeIndex: this.revokeIndex,
            "ability.want.params.uiExtensionTargetType": "photoPicker",
            uri: "multipleselect",
            targetPage: "photoPage",
            filterMediaType: this.convertMIMETypeToFilterType(this.pickerOptions?.MIMEType),
            MimeTypeFilter: this.parseMimeTypeFilter(this.pickerOptions?.MimeTypeFilter),
            fileSizeFilter: this.pickerOptions?.fileSizeFilter,
            videoDurationFilter: this.pickerOptions?.videoDurationFilter,
            maxSelectNumber: this.pickerOptions?.maxSelectNumber as number,
            isPhotoTakingSupported: this.pickerOptions?.isPhotoTakingSupported as boolean,
            isEditSupported: false,
            recommendationOptions: this.pickerOptions?.recommendationOptions as photoAccessHelper.RecommendationOptions,
            preselectedUri: this.pickerOptions?.preselectedUris as Array<string>,
            isFromPickerView: true,
            isNeedActionBar: false,
            isNeedSelectBar: false,
            isSearchSupported: this.pickerOptions?.isSearchSupported as boolean,
            checkBoxColor: this.pickerOptions?.checkBoxColor as string,
            backgroundColor: this.pickerOptions?.backgroundColor as string,
            checkboxTextColor: this.pickerOptions?.checkboxTextColor as string,
            photoBrowserBackgroundColorMode: this.pickerOptions?.photoBrowserBackgroundColorMode as PickerColorMode,
            isRepeatSelectSupported: this.pickerOptions?.isRepeatSelectSupported as boolean,
            maxSelectedReminderMode: this.pickerOptions?.maxSelectedReminderMode as ReminderMode,
            orientation: this.pickerOptions?.orientation as PickerOrientation,
            selectMode: this.pickerOptions?.selectMode as SelectMode,
            maxPhotoSelectNumber: this.pickerOptions?.maxPhotoSelectNumber as number,
            maxVideoSelectNumber: this.pickerOptions?.maxVideoSelectNumber as number,
            isOnItemClickedSet: this.onItemClicked ? true : false,
            isPreviewForSingleSelectionSupported: this.pickerOptions?.isPreviewForSingleSelectionSupported as boolean,
            singleSelectionMode: this.pickerOptions?.singleSelectionMode as number,
            isSlidingSelectionSupported: this.pickerOptions?.isSlidingSelectionSupported as boolean,
            photoBrowserCheckboxPosition: this.pickerOptions?.photoBrowserCheckboxPosition as [number, number],
            gridMargin: this.pickerOptions?.gridMargin as Margin,
            photoBrowserMargin: this.pickerOptions?.photoBrowserMargin as Margin
          }
        })
          .height('100%')
          .width('100%')
          .onRemoteReady((proxy) => {
            this.proxy = proxy;
            console.info('PhotoPickerComponent onRemoteReady');
          })
          .onReceive((data) => {
            let wantParam: Record<string, Object> = data as Record<string, Object>;
            this.handleOnReceive(wantParam);
          })
          .onError((error) => {
            console.info('PhotoPickerComponent onError: ' + JSON.stringify(error));
            console.info('PhotoPickerComponent revokeIndex: ' + this.revokeIndex);
            if (error.code === 100014 && this.revokeIndex < 3) {
              this.revokeIndex++;
            }
          });
      }
      .width('100%')
    }
    .height('100%')
  }

  private handleOnReceive(wantParam: Record<string, Object>): void {
    let dataType = wantParam['dataType'] as string;
    console.info('PhotoPickerComponent onReceive: dataType = ' + dataType);
    if (dataType === 'selectOrDeselect') {
      this.handleSelectOrDeselect(wantParam);
    } else if (dataType === 'itemClick') {
      this.handleItemClick(wantParam);
    } else if (dataType === 'onPhotoBrowserStateChanged') {
      this.handleEnterOrExitPhotoBrowser(wantParam);
    } else if (dataType === 'remoteReady') {
      if (this.onPickerControllerReady) {
        this.onPickerControllerReady();
        console.info('PhotoPickerComponent onReceive: onPickerControllerReady');
      }
    } else if (dataType === 'onPhotoBrowserChanged') {
      this.handlePhotoBrowserChange(wantParam);
    } else if (dataType === 'onVideoPlayStateChanged') {
      this.handleVideoPlayStateChange(wantParam)
    } else if (dataType === 'replaceCallback') {
      this.handleReplaceCallback(wantParam);
    } else if (dataType === 'createCallback') {
      this.handleCreateCallback(wantParam);
    } else if (dataType === 'saveCallback') {
      this.handleSaveCallback(wantParam);
    } else if (dataType === 'onBackground') {
      console.info('PhotoPickerComponent onReceive: onBackground');
      this.revokeIndex = 0;
    } else {
      this.handleOtherOnReceive(wantParam);
      console.info('PhotoPickerComponent onReceive: other case');
    }
    console.info('PhotoPickerComponent onReceive' + JSON.stringify(wantParam));
  }

  private handleOtherOnReceive(wantParam: Record<string, Object>): void {
    let dataType = wantParam.dataType as string;
    if (dataType === 'exceedMaxSelected') {
      if (this.onExceedMaxSelected) {
        this.onExceedMaxSelected(wantParam.maxCountType as MaxCountType);
      }
    } else if (dataType === 'selectedItemsDeleted') {
      if (this.onSelectedItemsDeleted) {
        this.onSelectedItemsDeleted(wantParam.selectedItemInfos as Array<BaseItemInfo>);
      }
    } else if (dataType === 'currentAlbumDeleted') {
      if (this.onCurrentAlbumDeleted) {
        this.onCurrentAlbumDeleted();
      }
    } else {
      console.info('PhotoPickerComponent onReceive: other case');
    }
  }

  private handleSelectOrDeselect(wantParam: Record<string, Object>): void {
    let isSelect: boolean = wantParam['isSelect'] as boolean;
    if (isSelect) {
      if (this.onSelect) {
        this.onSelect(wantParam['select-item-list'] as string);
        console.info('PhotoPickerComponent onReceive: onSelect');
      }
    } else {
      if (this.onDeselect) {
        this.onDeselect(wantParam['select-item-list'] as string);
        console.info('PhotoPickerComponent onReceive: onDeselect');
      }
    }
  }

  private handleItemClick(wantParam: Record<string, Object>): void {
    if (this.onItemClicked) {
      let clickType: ClickType = ClickType.SELECTED;
      let type = wantParam['clickType'] as string;
      if (type === 'select') {
        clickType = ClickType.SELECTED;
      } else if (type === 'deselect') {
        clickType = ClickType.DESELECTED;
      } else {
        console.info('PhotoPickerComponent onReceive: other clickType');
      }
      let itemInfo: ItemInfo = new ItemInfo();
      let itemType: string = wantParam['itemType'] as string;
      if (itemType === 'thumbnail') {
        itemInfo.itemType = ItemType.THUMBNAIL;
      } else if (itemType === 'camera') {
        itemInfo.itemType = ItemType.CAMERA;
      } else {
        console.info('PhotoPickerComponent onReceive: other itemType');
      }
      itemInfo.uri = wantParam['uri'] as string;
      itemInfo.mimeType = wantParam['mimeType'] as string;
      itemInfo.width = wantParam['width'] as number;
      itemInfo.height = wantParam['height'] as number;
      itemInfo.size = wantParam['size'] as number;
      itemInfo.duration = wantParam['duration'] as number;
      let result: boolean = this.onItemClicked(itemInfo, clickType);
      console.info('PhotoPickerComponent onReceive: onItemClicked = ' + clickType);
      if (this.proxy) {
        if (itemType === 'thumbnail' && clickType === ClickType.SELECTED) {
          this.proxy.send({ 'clickConfirm': itemInfo.uri, 'isConfirm': result });
          console.info('PhotoPickerComponent onReceive: click confirm: uri = ' + itemInfo.uri + 'isConfirm = ' +
            result);
        }
        if (itemType === 'camera') {
          this.proxy.send({ 'enterCamera': result });
          console.info('PhotoPickerComponent onReceive: enter camera ' + result);
        }
      }
    }
  }

  private handleEnterOrExitPhotoBrowser(wantParam: Record<string, Object>): void {
    let isEnter: boolean = wantParam['isEnter'] as boolean;
    let photoBrowserInfo: PhotoBrowserInfo = new PhotoBrowserInfo();
    photoBrowserInfo.animatorParams = new AnimatorParams();
    photoBrowserInfo.animatorParams.duration = wantParam['duration'] as number;
    photoBrowserInfo.animatorParams.curve = wantParam['curve'] as Curve | ICurve | string;
    if (isEnter) {
      if (this.onEnterPhotoBrowser) {
        this.onEnterPhotoBrowser(photoBrowserInfo);
      }
    } else {
      if (this.onExitPhotoBrowser) {
        this.onExitPhotoBrowser(photoBrowserInfo);
      }
    }
    console.info('PhotoPickerComponent onReceive: onPhotoBrowserStateChanged = ' + isEnter);
  }

  private handlePhotoBrowserChange(wantParam: Record<string, Object>): void {
    let browserItemInfo: BaseItemInfo = new BaseItemInfo();
    browserItemInfo.uri = wantParam['uri'] as string;
    if (this.onPhotoBrowserChanged) {
      this.onPhotoBrowserChanged(browserItemInfo);
    }
    console.info('PhotoPickerComponent onReceive: onPhotoBrowserChanged = ' + browserItemInfo.uri);
  }

  private handleVideoPlayStateChange(wantParam: Record<string, Object>): void {
    if (this.onVideoPlayStateChanged) {
      this.onVideoPlayStateChanged(wantParam.state as VideoPlayerState)
    }
    console.info('PhotoPickerComponent onReceive: onVideoPlayStateChanged = ' + JSON.stringify(wantParam));
  }

  private handleCreateCallback(wantParam: Record<string, Object>): void {
    this.pickerController.actionCreateCallback(wantParam['grantUri'] as string, wantParam['date'] as number,
      wantParam['code'] as number, wantParam['message'] as string);
    console.info('PhotoPickerComponent onReceive: handleCreateCallback');
  }

  private handleReplaceCallback(wantParam: Record<string, Object>): void {
    this.pickerController.actionReplaceCallback(wantParam['date'] as number,
      { 'name': '', 'code': wantParam['code'] as number, 'message': wantParam['message'] as string });
    console.info('PhotoPickerComponent onReceive: handleReplaceCallback');
  }

  private handleSaveCallback(wantParam: Record<string, Object>): void {
    this.pickerController.actionSaveCallback(wantParam['date'] as number,
      { 'name': '', 'code': wantParam['code'] as number, 'message': wantParam['error'] as string },
      wantParam['data'] as Array<string>);
    console.info('PhotoPickerComponent onReceive: handleSaveCallback');
  }

  parseMimeTypeFilter(filter?: photoAccessHelper.MimeTypeFilter): object | undefined {
    if (!filter) {
      return undefined;
    }
    let MimeTypeFilterObj: photoAccessHelper.MimeTypeFilter = {
      MimeTypeArray: [],
    };
    if (filter.MimeTypeArray) {
      for (let mimeType of filter.MimeTypeArray) {
        if (PHOTO_VIEW_MIME_TYPE_MAP.has(mimeType)) {
          o.MimeTypeArray.push(PHOTO_VIEW_MIME_TYPE_MAP.get(mimeType));
        } else {
          o.MimeTypeArray.push(mimeType);
        }
      }
    }
    return MimeTypeFilterObj;
  }

  private convertMIMETypeToFilterType(mimeType: photoAccessHelper.PhotoViewMIMETypes): string {
    let filterType: string;
    if (PHOTO_VIEW_MIME_TYPE_MAP.has(filterType)) {
      filterType = PHOTO_VIEW_MIME_TYPE_MAP.get(mimeType);
    } else {
      filterType = PHOTO_VIEW_MIME_TYPE_MAP.get('*/*);
    }
    console.info('PhotoPickerComponent convertMIMETypeToFilterType: ' + JSON.stringify(filterType));
    return filterType;
  }
}

export type ItemsDeletedCallback = (baseItemInfos: Array<BaseItemInfo>) => void;

export type ExceedMaxSelectedCallback = (exceedMaxCountType: MaxCountType) => void;

export type CurrentAlbumDeletedCallback = () => void;

export type VideoPlayStateChanged = (state: VideoPlayerState) => {} void;

@Observed
export class PickerController {
  data?: Map<string, Object>;
  replaceCallbackMap: Map<number, Object> = new Map<number, Object>();
  saveCallbackMap: Map<number, Object> = new Map<number, Object>();
  createCallbackMap: Map<number, Object> = new Map<number, Object>();

  setData(type: DataType, data: Object) {
    if (data === undefined) {
      return;
    }
    if (type === DataType.SET_SELECTED_URIS) {
      if (data instanceof Array) {
        let uriLists: Array<string> = data as Array<string>;
        if (uriLists) {
          this.data = new Map([['SET_SELECTED_URIS', [...uriLists]]]);
          console.info('PhotoPickerComponent SET_SELECTED_URIS' + JSON.stringify(uriLists));
        }
      }
    } else if (type === DataType.SET_ALBUM_URI) {
      let albumUri: string = data as string;
      if (albumUri !== undefined) {
        this.data = new Map([['SET_ALBUM_URI', albumUri]]);
        console.info('PhotoPickerComponent SET_ALBUM_URI' + JSON.stringify(albumUri));
      }
    } else {
      console.info('PhotoPickerComponent setData: other case');
    }
  }

  setMaxSelected(maxSelected: MaxSelected) {
    if (maxSelected) {
      this.data = new Map([['SET_MAX_SELECT_COUNT', maxSelected]]);
      console.info('PhotoPickerComponent SET_MAX_SELECT_COUNT' + JSON.stringify(maxSelected));
    }
  }

  setPhotoBrowserItem(uri: string, photoBrowserRange?: PhotoBrowserRange) {
    let photoBrowserRangeInfo: PhotoBrowserRangeInfo = new PhotoBrowserRangeInfo();
    photoBrowserRangeInfo.uri = uri;
    let newPhotoBrowserRange = photoBrowserRange ? photoBrowserRange : PhotoBrowserRange.ALL;
    photoBrowserRangeInfo.photoBrowserRange = newPhotoBrowserRange;
    this.data = new Map([['SET_PHOTO_BROWSER_ITEM', photoBrowserRangeInfo]]);
    console.info('PhotoPickerComponent SET_PHOTO_BROWSER_ITEM' + JSON.stringify(photoBrowserRangeInfo));
  }

  exitPhotoBrowser() {
    this.data = new Map([['EXIT_PHOTO_BROWSER', true]]);
    console.info('PhotoPickerComponent EXIT_PHOTO_BROWSER');
  }

  setPhotoBrowserUIElementVisibility(elements: Array<PhotoBrowserUIElement>, isVisible?: boolean) {
    let photoBrowserUIElementVisibility: PhotoBrowserUIElementVisibility = new PhotoBrowserUIElementVisibility();
    photoBrowserUIElementVisibility.elements = elements;
    photoBrowserUIElementVisibility.isVisible = isVisible;
    this.data = new Map([['SET_PHOTO_BROWSER_UI_ELEMENT_VISIBILITY', photoBrowserUIElementVisibility]]);
    console.info('PhotoPickerComponent SET_PHOTO_BROWSER_UI_ELEMENT_VISIBILITY ' +
    JSON.stringify(photoBrowserUIElementVisibility));
  }

  private async getAppName(): Promise<string> {
    let flags = bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_ABILITY | // for appName
    bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_HAP_MODULE | // for appName
    bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_SIGNATURE_INFO | // for appId
    bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_APPLICATION; // for appInfo
    let bundleInfo = bundleManager.getBundleInfoForSelfSync(flags);
    let labelId = bundleInfo.appInfo.labelId;
    let appName = '';
    let moduleName = '';
    for (let hapInfo of bundleInfo.hapModulesInfo) {
      if (labelId === hapInfo.labelId) {
        moduleName = hapInfo.name;
      }
    }
    appName = await getContext(this).createModuleContext(moduleName).resourceManager.getStringValue(labelId);
    return appName;
  }

  replacePhotoPickerPreview(selectedMediaUri: string, replaceUri: string, callback: AsyncCallback<void>) {
    try {
      let fd = fs.openSync(replaceUri).fd;
      fs.close(fd);
    } catch (err) {
      callback({'code': 13900002, 'message': 'No such file', name: ''});
      return;
    }
    let date = Math.random();
    this.data = new Map([['CREATE_URI', [selectedMediaUri, replaceUri, date]]]);
    this.createCallbackMap.set(date, (grantUri: string, code: number, message: string) => {
      if (code !== 0) {
        callback({ 'name': '', 'code': code, 'message': message });
        return;
      }
      let createFd = 0;
      let replaceFd = 0;
      try {
        createFd = fs.openSync(grantUri, fs.OpenMode.READ_WRITE).fd;
        replaceFd = fs.openSync(replaceUri, fs.OpenMode.READ_ONLY).fd;
        fs.copyFileSync(replaceFd, createFd);
        this.data = new Map([['REPLACE_URI', [selectedMediaUri, grantUri, date]]]);
        this.replaceCallbackMap.set(date, callback);
      } catch (err) {
        callback({ 'code': 14000011, 'message': 'System inner fail', name: '' });
      } finally {
        fs.close(createFd);
        fs.close(replaceFd);
      }
    })
  }

  saveTrustedPhotoAssets(selectedMediaUris: Array<string>, callback: AsyncCallback<Array<string>>,
    config?: Array<photoAccessHelper.PhotoCreationConfig>, saveMode?: SaveMode) {
    if (!selectedMediaUris || selectedMediaUris.length === 0) {
      callback({'code': 14000002, 'message': 'Invalid URI', name: ''}, []);
      return;
    }
    this.getAppName().then((appName: string)=>{
      let date = Math.random();
      this.data = new Map([['SAVE_TRUSTED_PHOTO_ASSETS', [selectedMediaUris, config, saveMode, appName, date]]]);
      this.saveCallbackMap.set(date, callback);
    })
    console.info('PhotoPickerComponent SAVE_TRUSTED_PHOTO_ASSETS ');
  }

  actionCreateCallback(grantUri: string, date: number, code: number, message: string) {
    if (this.createCallbackMap.has(date)) {
      let callback = this.createCallbackMap.get(date) as Function;
      if (callback) {
        callback(grantUri, code, message);
        this.createCallbackMap.delete(date);
      }
    }
  }

  actionReplaceCallback(date: number, err: BusinessError) {
    if (this.replaceCallbackMap.has(date)) {
      let callback = this.replaceCallbackMap.get(date) as Function;
      if (callback) {
        callback(err);
        this.replaceCallbackMap.delete(date);
      }
    }
  }

  actionSaveCallback(date: number, err: BusinessError, data: Array<string>) {
    if (this.saveCallbackMap.has(date)) {
      let callback = this.saveCallbackMap.get(date) as Function;
      if (callback) {
        callback(err, data);
        this.saveCallbackMap.delete(date);
      }
    }
  }
}

export class PickerOptions extends photoAccessHelper.BaseSelectOptions {
  checkBoxColor?: string;
  backgroundColor?: string;
  isRepeatSelectSupported?: boolean;
  checkboxTextColor?: string;
  photoBrowserBackgroundColorMode?: PickerColorMode;
  maxSelectedReminderMode?: ReminderMode;
  orientation?: PickerOrientation;
  selectMode?: SelectMode;
  maxPhotoSelectNumber?: number;
  maxVideoSelectNumber?: number;
  isSlidingSelectionSupported?: boolean;
  photoBrowserCheckboxPosition?: [number, number];
  gridMargin?: Margin;
  photoBrowserMargin?: Margin; 
}

export class BaseItemInfo {
  uri?: string;
  mimeType?: string;
  width?: number;
  height?: number;
  size?: number;
  duration?: number;
}

export class ItemInfo extends BaseItemInfo {
  itemType?: ItemType;
}

export class PhotoBrowserInfo {
  animatorParams?: AnimatorParams;
}

export class AnimatorParams {
  duration?: number;
  curve?: Curve | ICurve | string;
}

export class MaxSelected {
  data?: Map<MaxCountType, number>;
}

class PhotoBrowserRangeInfo {
  uri?: string;
  photoBrowserRange?: PhotoBrowserRange;
}

class PhotoBrowserUIElementVisibility {
  elements?: Array<PhotoBrowserUIElement>;
  isVisible?: boolean;
}

export enum DataType {
  SET_SELECTED_URIS = 1,
  SET_ALBUM_URI = 2
}

export enum ItemType {
  THUMBNAIL = 0,
  CAMERA = 1
}

export enum ClickType {
  SELECTED = 0,
  DESELECTED = 1
}

export enum PickerOrientation {
  VERTICAL = 0,
  HORIZONTAL = 1
}

export enum SelectMode {
  SINGLE_SELECT = 0,
  MULTI_SELECT = 1
}

export enum PickerColorMode {
  AUTO = 0,
  LIGHT = 1,
  DARK = 2
}

export enum ReminderMode {
  NONE = 0,
  TOAST = 1,
  MASK = 2
}

export enum MaxCountType {
  TOTAL_MAX_COUNT = 0,
  PHOTO_MAX_COUNT = 1,
  VIDEO_MAX_COUNT = 2
}

export enum PhotoBrowserRange {
  ALL = 0,
  SELECTED_ONLY = 1
}

export enum PhotoBrowserUIElement {
  CHECKBOX = 0,
  BACK_BUTTON = 1
}

export enum VideoPlayerState {
  PLAYING = 0,
  PAUSED = 1,
  STOPPED = 3,
  SEEK_START = 4,
  SEEK_FINISH = 5
}

export enum SaveMode {
  SAVE_AS = 0,
  OVERWRITE = 1
}