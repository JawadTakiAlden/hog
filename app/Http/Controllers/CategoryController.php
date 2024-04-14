<?php

namespace App\Http\Controllers;

use App\Http\HelperFunction;
use App\Http\Resources\CategoryResource;
use App\HttpResponse\HTTPResponse;
use App\Models\Category;
use App\Http\Requests\StoreCategoryRequest;
use App\Http\Requests\UpdateCategoryRequest;

class CategoryController extends Controller
{
    use HTTPResponse;
    public function gelAllCategories(){
        try {
            $categories = Category::all();
            return $this->success(CategoryResource::collection($categories));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }
    public function visibleCategories(){
        try {
            $categories = Category::where('is_visible' , true)->get();
            return $this->success(CategoryResource::collection($categories));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function switchVisibility($categoryID){
        try {
            $category = HelperFunction::getCategoryByID($categoryID);
            if (!$category) {
                return $this->error(__("messages.error.not_found") , 404);
            }
            $category->update([
                'is_visible' => !$category->is_visible
            ]);
            return $this->success(CategoryResource::make($category) , $category->name . ' updated successfully');
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function store(StoreCategoryRequest $request){
        $request->validated($request->only(['name','is_visible']));
        try {
            $category = Category::create($request->only(['name','is_visible']));
            return $this->success(CategoryResource::make($category) , __('messages.category_controller.create_category'));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function show($categoryID){
        try {
            $category = HelperFunction::getCategoryByID($categoryID);
            if (!$category) {
                return $this->error(__("messages.error.not_found"), 404);
            }
            return $this->success(CategoryResource::make($category));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function updateCategory(UpdateCategoryRequest $request , $categoryID){
        try {
            $category = HelperFunction::getCategoryByID($categoryID);
            if (!$category) {
                return $this->error(__("messages.error.not_found") , 404);
            }
            $category->update($request->only(['name' , 'is_visible']));
            return $this->success(CategoryResource::make($category) , __('messages.category_controller.update_category'));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function destroy($categoryID){
        try {
            $category = HelperFunction::getCategoryByID($categoryID);
            if (!$category) {
                return $this->error(__("messages.error.not_found") , 404);
            }
            $category->delete();
            return $this->success(CategoryResource::make($category) ,__('messages.category_controller.delete_category') );
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }
}
