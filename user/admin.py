from django.contrib import admin
from django import forms
from datetime import date
from django.contrib.auth.hashers import make_password
from .models import *
from .security import password_error

# Register your models here.
admin.site.register(city)
admin.site.register(state)
admin.site.register(category)

GENDER_CHOICES = [('male', 'Male'), ('female', 'Female')]

# class UserForm(forms.ModelForm):
#     gender = forms.ChoiceField(choices=GENDER_CHOICES, widget=forms.RadioSelect)
#     state_select = forms.ModelChoiceField(
#         queryset=state.objects.all(),
#         required=False,
#         label='State',
#         widget=forms.Select(attrs={'id': 'id_state_select'}),
#     )

#     class Meta:
#         model = user
#         fields = '__all__'
#         widgets = {
#             'dob': forms.DateInput(attrs={
#                 'type': 'date',
#                 'max': date.today().isoformat(),
#             }),
#         }

#     def __init__(self, *args, **kwargs):
#         super().__init__(*args, **kwargs)
#         # Pre-select the state if editing an existing user
#         if self.instance and self.instance.pk and self.instance.cityid:
#             self.fields['state_select'].initial = self.instance.cityid.stateid

#     class Media:
#         js = ('admin/js/admin_state_city.js',)


class UserForm(forms.ModelForm):
    gender = forms.ChoiceField(choices=GENDER_CHOICES, widget=forms.RadioSelect)
    state_select = forms.ModelChoiceField(
        queryset=state.objects.all(),
        required=False,
        label='State',
        widget=forms.Select(attrs={'id': 'id_state_select'}),
    )
    new_password = forms.CharField(
        required=False,
        label='Set new password',
        widget=forms.PasswordInput(render_value=False, attrs={'autocomplete': 'new-password'}),
        help_text='Leave blank to keep the current password. Passwords are stored hashed and can never be viewed.',
    )

    class Meta:
        model = user
        # password: never shown (use "Set new password" below).
        # last_*: maintained automatically by the app. They were rendered as hidden
        # inputs that failed validation, so any user who had ever logged in could
        # not be saved from this page.
        exclude = ('password', 'last_checked_chats', 'last_checked_activity',
                   'last_checked_invites', 'last_seen')
        widgets = {
            'dob': forms.DateInput(attrs={
                'type': 'date',
                'max': date.today().isoformat(),
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk and self.instance.cityid:
            self.fields['state_select'].initial = self.instance.cityid.stateid

    def clean_new_password(self):
        pw = self.cleaned_data.get('new_password')
        if pw:
            err = password_error(pw)
            if err:
                raise forms.ValidationError(err)
        return pw

    class Media:
        js = ('admin/js/admin_state_city.js',)


@admin.register(user)
class UserAdmin(admin.ModelAdmin):
    form = UserForm
    list_display = ('userid', 'username', 'email', 'gender', 'registrationdt')
    search_fields = ('username', 'email')

    def save_model(self, request, obj, form, change):
        new_pw = form.cleaned_data.get('new_password')
        if new_pw:
            obj.password = make_password(new_pw)
        elif not change:
            obj.password = make_password(None)  # unusable until a password is set
        super().save_model(request, obj, form, change)

    class Media:
        js = ('admin/js/admin_state_city.js',)

@admin.register(community)
class CommunityAdmin(admin.ModelAdmin):
    list_display = ('communityid', 'communitytitle', 'categoryid', 'userid', 'createddt')
    search_fields = ('communitytitle',)
    list_filter = ('categoryid',)

@admin.register(communitymember)
class CommunityMemberAdmin(admin.ModelAdmin):
    list_display = ('communitymemberid', 'communityid', 'userid', 'role', 'status', 'addeddt')
    search_fields = ('userid__username', 'userid__email')
    list_filter = ('role', 'status')

@admin.register(communityAdmins)
class CommunityAdminsAdmin(admin.ModelAdmin):
    list_display = ('communityAdminsid', 'communityid', 'adminid', 'addedbyuserid', 'addeddt')
    search_fields = ('adminid__username',)

@admin.register(post)
class PostAdmin(admin.ModelAdmin):
    list_display = ('postid', 'posttitle', 'communityid', 'userid', 'isapproved', 'createddt')
    list_filter = ('isapproved',)
    search_fields = ('posttitle',)

@admin.register(comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ('commentid', 'postid', 'userid', 'createddt')

@admin.register(like)
class LikeAdmin(admin.ModelAdmin):
    list_display = ('likeid', 'postid', 'userid')

@admin.register(blog)
class BlogAdmin(admin.ModelAdmin):
    list_display = ('blogid', 'title', 'author', 'createddt')
    search_fields = ('title', 'description')
    list_filter = ('categoryid',)

@admin.register(meetup)
class MeetupAdmin(admin.ModelAdmin):
    list_display = ('meetupid', 'title', 'meetup_type', 'communityid', 'meeting_date', 'created_by', 'createddt')
    search_fields = ('title', 'description')
    list_filter = ('meetup_type', 'communityid')
@admin.register(ContactMessage)
class ContactMessageAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'subject', 'is_read', 'created_at')
    list_editable = ('is_read',)
    list_filter = ('is_read', 'created_at')
    search_fields = ('name', 'email', 'subject', 'message')
    readonly_fields = ('created_at',)
