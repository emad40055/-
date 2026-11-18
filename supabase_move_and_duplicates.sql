-- Run once in Supabase SQL Editor before using move / duplicate-safe check-in.
create or replace function public.sakan_safe_check_in(p_room integer,p_bed integer,p_name text,p_phone text)
returns void language plpgsql security definer set search_path=public as $$
declare v_phone text; v_existing record;
begin
 if auth.uid() is null or not public.is_sakan_admin() then raise exception 'غير مصرح'; end if;
 if p_bed not between 1 and 3 or nullif(btrim(p_name),'') is null or nullif(btrim(p_phone),'') is null then raise exception 'بيانات الطالب غير مكتملة'; end if;
 v_phone:=regexp_replace(p_phone,'[^0-9]','','g');
 if length(v_phone)<7 then raise exception 'رقم الجوال غير صحيح'; end if;
 perform pg_advisory_xact_lock(824116);
 select room_number,student_name into v_existing from public.students
 where checked_out_at is null and regexp_replace(coalesce(phone,''),'[^0-9]','','g')=v_phone limit 1;
 if found then raise exception 'رقم الجوال مسجل مسبقاً للطالب % في الغرفة %',v_existing.student_name,v_existing.room_number; end if;
 if not exists(select 1 from public.rooms where room_number=p_room) then raise exception 'الغرفة غير موجودة'; end if;
 insert into public.students(room_number,bed_number,student_name,phone,checked_in_at)
 values(p_room,p_bed,btrim(p_name),btrim(p_phone),now());
end;$$;
create or replace function public.sakan_move_student(p_student_id uuid,p_room integer,p_bed integer)
returns void language plpgsql security definer set search_path=public as $$
declare v_student public.students%rowtype;
begin
 if auth.uid() is null or not public.is_sakan_admin() then raise exception 'غير مصرح'; end if;
 if p_bed not between 1 and 3 then raise exception 'رقم السرير غير صحيح'; end if;
 perform pg_advisory_xact_lock(824116);
 select * into v_student from public.students where id=p_student_id and checked_out_at is null for update;
 if not found then raise exception 'الطالب غير موجود أو تم إخلاؤه'; end if;
 if not exists(select 1 from public.rooms where room_number=p_room) then raise exception 'الغرفة غير موجودة'; end if;
 if exists(select 1 from public.students where room_number=p_room and bed_number=p_bed and checked_out_at is null and id<>p_student_id) then raise exception 'السرير محجوز من مشرف آخر'; end if;
 if v_student.room_number=p_room and v_student.bed_number=p_bed then return; end if;
 update public.students set room_number=p_room,bed_number=p_bed where id=p_student_id;
 -- Return old room key to reception if it was held by the moving student.
 update public.rooms set key_holder='reception'
 where room_number=v_student.room_number and key_holder=v_student.student_name;
end;$$;
revoke all on function public.sakan_safe_check_in(integer,integer,text,text) from public;
revoke all on function public.sakan_move_student(uuid,integer,integer) from public;
grant execute on function public.sakan_safe_check_in(integer,integer,text,text) to authenticated;
grant execute on function public.sakan_move_student(uuid,integer,integer) to authenticated;
